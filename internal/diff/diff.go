// Package diff queries a bounded set of DNS resolvers and compares answer sets.
package diff

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const MaxResolvers = 16

// Types deliberately excludes zone transfers and ANY queries.
var Types = map[string]uint16{
	"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CAA": dns.TypeCAA,
	"CNAME": dns.TypeCNAME, "DNAME": dns.TypeDNAME, "MX": dns.TypeMX,
	"NS": dns.TypeNS, "PTR": dns.TypePTR, "SOA": dns.TypeSOA,
	"SRV": dns.TypeSRV, "TXT": dns.TypeTXT,
}

type Config struct {
	Name      string
	Type      uint16
	Resolvers []string
	Timeout   time.Duration
	TCP       bool
	Recurse   bool
}

type Result struct {
	Resolver  string   `json:"resolver"`
	Transport string   `json:"transport"`
	Rcode     string   `json:"rcode,omitempty"`
	Answers   []string `json:"answers"`
	Error     string   `json:"error,omitempty"`
	Group     int      `json:"group,omitempty"`
}

type Report struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Status  string   `json:"status"`
	Results []Result `json:"results"`
}

// Resolver accepts IP literals, optionally with a port. Hostnames are excluded
// so resolving a resolver cannot depend on a different, implicit DNS service.
func Resolver(s string) (string, error) {
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		return netip.AddrPortFrom(ip.Unmap(), 53).String(), nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 && ap.Addr().Zone() == "" {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), nil
	}
	return "", fmt.Errorf("invalid resolver %q: use an IP, IPv4:port, or [IPv6]:port", s)
}

// Name validates presentation-format DNS names and produces a stable spelling.
// Unicode input must be converted to an IDNA A-label by the caller.
func Name(s string) (string, error) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return "", fmt.Errorf("invalid name %q: use ASCII DNS labels (punycode for IDNs)", s)
	}
	n := dns.Fqdn(s)
	if _, ok := dns.IsDomainName(n); !ok {
		return "", fmt.Errorf("invalid DNS name %q", s)
	}
	return canonicalName(n)
}

// Run preserves resolver order, even though all queries run concurrently.
func Run(ctx context.Context, cfg Config) Report {
	r := Report{Name: cfg.Name, Type: dns.TypeToString[cfg.Type], Results: make([]Result, len(cfg.Resolvers))}
	var wg sync.WaitGroup
	for i, resolver := range cfg.Resolvers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Results[i] = query(ctx, cfg, resolver)
		}()
	}
	wg.Wait()
	groups := make(map[string]int)
	r.Status = "agree"
	for i := range r.Results {
		result := &r.Results[i]
		if result.Error != "" {
			r.Status = "error"
			continue
		}
		key := result.Rcode + "\x00" + strings.Join(result.Answers, "\x00")
		if groups[key] == 0 {
			groups[key] = len(groups) + 1
		}
		result.Group = groups[key]
	}
	if r.Status != "error" && len(groups) > 1 {
		r.Status = "differ"
	}
	return r
}

func query(ctx context.Context, cfg Config, resolver string) (result Result) {
	result = Result{Resolver: resolver, Transport: "udp", Answers: []string{}}
	if cfg.TCP {
		result.Transport = "tcp"
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion(cfg.Name, cfg.Type)
	q.RecursionDesired = cfg.Recurse
	q.SetEdns0(1232, false)
	exchange := func() (*dns.Msg, error) {
		client := dns.Client{Net: result.Transport, Timeout: cfg.Timeout, UDPSize: 1232}
		conn, err := client.DialContext(ctx, resolver)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		// ExchangeWithConnContext applies deadlines, but cancellation after
		// dialing needs to interrupt an in-flight read explicitly.
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		m, _, err := client.ExchangeWithConnContext(ctx, q, conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if !m.Response || m.Opcode != dns.OpcodeQuery || m.Id != q.Id || len(m.Question) != 1 {
			return nil, fmt.Errorf("invalid DNS response header or question")
		}
		question := m.Question[0]
		name, err := canonicalName(question.Name)
		if err != nil || name != cfg.Name || question.Qtype != cfg.Type || question.Qclass != dns.ClassINET {
			return nil, fmt.Errorf("response question does not match query")
		}
		return m, nil
	}
	m, err := exchange()
	if err == nil && m.Truncated && result.Transport == "udp" {
		result.Transport = "tcp"
		m, err = exchange()
	}
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Rcode = dns.RcodeToString[m.Rcode]
	if result.Rcode == "" {
		result.Rcode = "RCODE" + strconv.Itoa(m.Rcode)
	}
	if m.Truncated {
		result.Error = "truncated TCP response"
		return
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		result.Error = "resolver returned " + result.Rcode
		return
	}
	// A referral is not a complete negative answer. Do not call two matching
	// referrals agreement about the queried records.
	if m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0 && !m.Authoritative {
		hasNS, hasSOA := false, false
		for _, rr := range m.Ns {
			hasNS = hasNS || rr.Header().Rrtype == dns.TypeNS
			hasSOA = hasSOA || rr.Header().Rrtype == dns.TypeSOA
		}
		if hasNS && !hasSOA {
			result.Error = "referral response; query a recursive resolver or the authoritative server for this name"
			return
		}
	}
	for _, rr := range m.Answer {
		answer, err := canonicalRR(rr)
		if err != nil {
			result.Error = err.Error()
			result.Answers = []string{}
			return
		}
		result.Answers = append(result.Answers, answer)
	}
	slices.Sort(result.Answers)
	result.Answers = slices.Compact(result.Answers)
	return
}

// canonicalName normalizes ASCII case and alternate escaped spellings on the
// wire; it does not lowercase arbitrary RDATA (notably TXT and CAA values).
func canonicalName(name string) (string, error) {
	wire := make([]byte, 256)
	n, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil || n > 255 {
		return "", fmt.Errorf("invalid domain name %q", name)
	}
	for i := 0; i < n; {
		length := int(wire[i])
		i++
		for end := i + length; i < end; i++ {
			if wire[i] >= 'A' && wire[i] <= 'Z' {
				wire[i] += 'a' - 'A'
			}
		}
	}
	out, _, err := dns.UnpackDomainName(wire[:n], 0)
	return out, err
}

func canonicalRR(original dns.RR) (string, error) {
	rr := dns.Copy(original)
	h := rr.Header()
	var err error
	h.Name, err = canonicalName(h.Name)
	if err != nil {
		return "", err
	}
	if h.Class != dns.ClassINET {
		return "", fmt.Errorf("unsupported answer class %d", h.Class)
	}
	h.Ttl = 0
	var names []*string
	switch v := rr.(type) {
	case *dns.A, *dns.AAAA, *dns.TXT:
	case *dns.CAA:
		v.Tag = strings.ToLower(v.Tag)
	case *dns.CNAME:
		names = []*string{&v.Target}
	case *dns.DNAME:
		names = []*string{&v.Target}
	case *dns.NS:
		names = []*string{&v.Ns}
	case *dns.PTR:
		names = []*string{&v.Ptr}
	case *dns.MX:
		names = []*string{&v.Mx}
	case *dns.SRV:
		names = []*string{&v.Target}
	case *dns.SOA:
		names = []*string{&v.Ns, &v.Mbox}
	default:
		return "", fmt.Errorf("unsupported answer record type %d", h.Rrtype)
	}
	for _, name := range names {
		*name, err = canonicalName(*name)
		if err != nil {
			return "", err
		}
	}
	// Strip only the header TTL, not numeric RDATA such as MX preference.
	return strings.Replace(rr.String(), "\t0\t", "\t", 1), nil
}
