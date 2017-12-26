package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/YueHonghui/rfw"
	"github.com/miekg/dns"
	"github.com/zmap/go-iptree/iptree"
)

var (
	blacklist_path          string
	chnroute_path           string
	bid_filter              bool
	delay_time              float64
	bind_addr               string
	bind_port               int
	upstreams               string
	dns_pointer_compression bool
	verbose                 bool
	version                 bool
	logpath                 string
)

var (
	primaryUpstream string
	backupUpstream  string
	tcpcli          *dns.Client = &dns.Client{
		Net:     "tcp",
		Timeout: 2 * time.Second,
	}
	udpcli *dns.Client = &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}
	chn       *iptree.IPTree
	blacklist []string
	logger    *log.Logger
)

const (
	primary_timeout time.Duration = 200 * time.Millisecond
	backup_timeout  time.Duration = 1000 * time.Millisecond
)

func initBlacklist() error {
	if blacklist_path == "" {
		return nil
	}
	f, err := os.OpenFile(blacklist_path, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txt := scanner.Text()
		blacklist = append(blacklist, strings.TrimSpace(txt))
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	sort.Strings(blacklist)
	return nil
}

func initChn() error {
	f, err := os.OpenFile(chnroute_path, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	chn = iptree.New()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txt := scanner.Text()
		if err = chn.AddByString(txt, struct{}{}); err != nil {
			return err
		}
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	return nil
}

func is_blacklist(ip string) bool {
	if i := sort.SearchStrings(blacklist, ip); i < len(blacklist) && blacklist[i] == ip {
		return true
	}
	return false
}

func is_chnroute(ip string) bool {
	if _, ok, err := chn.GetByString(ip); err == nil && ok {
		return true
	}
	return false
}

func rank(is_primary bool, r dns.RR) (score int) {
	defer func() {
		if is_primary {
			score += 1
		}
	}()
	if r.Header().Rrtype != dns.TypeA {
		return 10
	}
	var a *dns.A
	var ok bool
	if a, ok = r.(*dns.A); !ok {
		return 0
	}
	if is_blacklist(a.A.String()) {
		return 0
	}
	if is_primary == is_chnroute(a.A.String()) {
		return 20
	}
	return 8
}

func lookup(remote string, is_primary bool, r *dns.Msg) (m *dns.Msg, rtt time.Duration, score int, err error) {
	cli := tcpcli
	timeout := backup_timeout
	if is_primary {
		cli = udpcli
		timeout = primary_timeout
	}
	subctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if m, rtt, err = cli.ExchangeContext(subctx, r, remote); err != nil {
		return
	}
	if len(m.Answer) == 0 {
		score = 8
		return
	}
	score = -1
	for _, a := range m.Answer {
		r := rank(is_primary, a)
		if score < 0 {
			score = r
		} else if r < score {
			score = r
		}
	}
	return
}

func fireLookup(r *dns.Msg) (m *dns.Msg, err error) {
	var ms [2]*dns.Msg
	var rtts [2]time.Duration
	var scores [2]int
	var errs [2]error
	ups := [2]string{primaryUpstream, backupUpstream}
	ius := [2]bool{true, false}
	wg := &sync.WaitGroup{}
	for i := 0; i < len(ups); i++ {
		wg.Add(1)
		go func(idx int) {
			ms[idx], rtts[idx], scores[idx], errs[idx] = lookup(ups[idx], ius[idx], r)
			wg.Done()
		}(i)
	}
	wg.Wait()
	tidx := 0
	tscore := -2
	for i := 0; i < len(ups); i++ {
		if errs[i] != nil {
			logger.Printf("lookup %s @%s failed: %v\n", r.Question[0].String(), ups[i], errs[i])
			continue
		}
		if scores[i] > tscore {
			tscore = scores[i]
			tidx = i
		}
	}
	m, err = ms[tidx], errs[tidx]
	return
}

func handleLookup(w dns.ResponseWriter, r *dns.Msg) {
	var m *dns.Msg
	var err error
	m, err = fireLookup(r)
	if err != nil {
		logger.Printf("lookup from %s failed: %v\n", primaryUpstream, err)
		m = new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
		return
	}
	w.WriteMsg(m)
}

func parseAddr(ipport string) (ip string, port int, err error) {
	is := strings.Split(ipport, ":")
	if len(is) > 2 {
		return "", -1, errors.New("has multiple :")
	}
	if len(is) == 1 {
		return ipport, -1, nil
	}
	if port, err = strconv.Atoi(is[1]); err != nil {
		return is[0], port, nil
	}
	return "", -1, fmt.Errorf("port %s invalid", is[1])
}

func parseUpstream() error {
	us := strings.Split(upstreams, ",")
	if len(us) != 2 {
		return errors.New("must has two upstream server")
	}
	pip, pport, err := parseAddr(us[0])
	if err != nil {
		return fmt.Errorf("parse upstream %s failed: %v", us[0], err)
	}
	bip, bport, err := parseAddr(us[1])
	if err != nil {
		return fmt.Errorf("parse upstream %s failed: %v", us[1], err)
	}
	if pport == -1 {
		pport = 53
	}
	if bport == -1 {
		bport = 53
	}
	primaryUpstream = fmt.Sprintf("%s:%d", pip, pport)
	backupUpstream = fmt.Sprintf("%s:%d", bip, bport)
	return nil
}

func main() {
	flag.StringVar(&blacklist_path, "l", "", "path to ip blacklist file")
	flag.StringVar(&chnroute_path, "c", "./chinaroute.txt", "path to china route file")
	flag.BoolVar(&bid_filter, "d", false, "off enable bi-directional CHNRoute filter")
	flag.Float64Var(&delay_time, "y", 0.3, "delay time for suspects")
	flag.StringVar(&bind_addr, "b", "0.0.0.0", "address that listens")
	flag.IntVar(&bind_port, "p", 53, "port that listens")
	flag.StringVar(&upstreams, "s", "223.6.6.6,8.8.4.4", "DNS servers to use")
	flag.BoolVar(&dns_pointer_compression, "m", false, "use DNS compression pointer mutation")
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.BoolVar(&version, "V", false, "print version and exit")
	flag.StringVar(&logpath, "logpath", "/var/log/chaindns", "logpath")
	flag.Parse()
	if version {
		fmt.Println("version: 1.0")
		return
	}
	logf, err := rfw.NewWithOptions(logpath, rfw.WithCleanUp(3))
	if err != nil {
		log.Fatalf("create rfw failed: %v\n", err)
	}
	logger = log.New(logf, "", log.Lshortfile|log.Ltime|log.Ldate)
	if err := parseUpstream(); err != nil {
		logger.Fatalf("parseUpstream %s failed: %v\n", upstreams, err)
	}
	if err := initChn(); err != nil {
		logger.Fatalf("init Chn file %s failed: %v\n", chnroute_path, err)
	}
	if err := initBlacklist(); err != nil {
		logger.Fatalf("init blacklist file %s failed: %v\n", blacklist_path, err)
	}
	listen := fmt.Sprintf("%s:%d", bind_addr, bind_port)
	dns.HandleFunc(".", handleLookup)
	stcp := &dns.Server{Addr: listen, Net: "tcp"}
	go stcp.ListenAndServe()
	sudp := &dns.Server{Addr: listen, Net: "udp"}
	sudp.ListenAndServe()
}
