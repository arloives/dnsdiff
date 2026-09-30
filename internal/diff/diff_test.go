package diff

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arloives/dnsdiff/internal/testdns"
	"github.com/miekg/dns"
)

func config(resolvers ...string) Config {
	return Config{Name: "example.test.", Type: dns.TypeA, Resolvers: resolvers, Timeout: time.Second, Recurse: true}
}

func TestResolver(t *testing.T) {
	for input, want := range map[string]string{
		"1.1.1.1": "1.1.1.1:53", "127.0.0.1:5353": "127.0.0.1:5353",
		"2001:db8::1": "[2001:db8::1]:53", "[::1]:5353": "[::1]:5353",
		"::ffff:192.0.2.1": "192.0.2.1:53",
	} {
		got, err := Resolver(input)
		if err != nil || got != want {
			t.Errorf("Resolver(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "dns.example", "https://1.1.1.1/dns-query", "1.1.1.1:0", "1.1.1.1:65536", "[fe80::1%eth0]:53", "1.1.1.1:foo"} {
		if _, err := Resolver(input); err == nil {
			t.Errorf("accepted invalid resolver %q", input)
		}
	}
}

func TestName(t *testing.T) {
	for input, want := range map[string]string{
		"EXample.Test": "example.test.", `\069xample.test.`: "example.test.", ".": ".", "_sip._tcp.example.test": "_sip._tcp.example.test.",
	} {
		got, err := Name(input)
		if err != nil || got != want {
			t.Errorf("Name(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "has space.test", "two..dots.test", "café.test", strings.Repeat("a", 64) + ".test", strings.Repeat("abcd.", 52)} {
		if _, err := Name(input); err == nil {
			t.Errorf("accepted invalid name %q", input)
		}
	}
}

func TestComparison(t *testing.T) {
	tests := []struct {
		name        string
		left, right []string
		rightRcode  int
		status      string
	}{
		{"order, TTL, case, duplicates", []string{"EXAMPLE.test. 40 IN A 192.0.2.2", "example.test. 60 IN A 192.0.2.1"}, []string{"example.TEST. 1 IN A 192.0.2.1", "example.test. 99 IN A 192.0.2.2", "example.test. 99 IN A 192.0.2.2"}, 0, "agree"},
		{"different address", []string{"example.test. 60 IN A 192.0.2.1"}, []string{"example.test. 60 IN A 192.0.2.2"}, 0, "differ"},
		{"empty and NXDOMAIN", nil, nil, dns.RcodeNameError, "differ"},
		{"empty matches empty", nil, nil, 0, "agree"},
		{"failure is not data", nil, nil, dns.RcodeServerFailure, "error"},
		{"refused is error", nil, nil, dns.RcodeRefused, "error"},
		{"CNAME target case", []string{"example.test. 60 IN CNAME TARGET.test."}, []string{"example.test. 3 IN CNAME target.test."}, 0, "agree"},
		{"CNAME owner matters", []string{"example.test. 60 IN CNAME target.test."}, []string{"else.test. 60 IN CNAME target.test."}, 0, "differ"},
		{"TXT case matters", []string{`example.test. 60 IN TXT "Token"`}, []string{`example.test. 60 IN TXT "token"`}, 0, "differ"},
		{"TXT boundaries matter", []string{`example.test. 60 IN TXT "ab" "cd"`}, []string{`example.test. 60 IN TXT "abcd"`}, 0, "differ"},
		{"CAA tag case", []string{`example.test. 60 IN CAA 0 ISSUE "ca.test"`}, []string{`example.test. 60 IN CAA 0 issue "ca.test"`}, 0, "agree"},
		{"CAA value case matters", []string{`example.test. 60 IN CAA 0 issue "CA.test"`}, []string{`example.test. 60 IN CAA 0 issue "ca.test"`}, 0, "differ"},
		{"DNAME target case", []string{"example.test. 60 IN DNAME TARGET.test."}, []string{"example.test. 60 IN DNAME target.test."}, 0, "agree"},
		{"SOA serial matters", []string{"example.test. 60 IN SOA ns.test. hostmaster.test. 1 2 3 4 5"}, []string{"example.test. 60 IN SOA ns.test. hostmaster.test. 2 2 3 4 5"}, 0, "differ"},
		{"unknown answer type rejected", []string{"example.test. 60 IN DNSKEY 256 3 8 AQAB"}, nil, 0, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			left := testdns.Start(t, testdns.Reply(0, tt.left...))
			right := testdns.Start(t, testdns.Reply(tt.rightRcode, tt.right...))
			cfg := config(left, right)
			got := Run(context.Background(), cfg)
			if got.Status != tt.status {
				t.Fatalf("status = %q; want %q: %+v", got.Status, tt.status, got.Results)
			}
			if got.Results[0].Resolver != left || got.Results[1].Resolver != right {
				t.Fatal("input order not preserved")
			}
		})
	}
}

func TestCanonicalRecordFields(t *testing.T) {
	for _, input := range []string{
		"EXAMPLE.test. 60 IN MX 10 MAIL.test.", "EXAMPLE.test. 60 IN NS NS.test.",
		"EXAMPLE.test. 60 IN PTR PTR.test.", "EXAMPLE.test. 60 IN SRV 1 2 443 SRV.test.",
		"EXAMPLE.test. 60 IN SOA NS.test. HOST.test. 1 2 3 4 5",
		"EXAMPLE.test. 60 IN AAAA 2001:db8::1",
	} {
		rr, _ := dns.NewRR(input)
		before := rr.String()
		got, err := canonicalRR(rr)
		if err != nil {
			t.Fatalf("canonicalRR(%q) = %q, %v", input, got, err)
		}
		if strings.Contains(got, "EXAMPLE") || strings.Contains(got, "MAIL") || strings.Contains(got, "NS.test") || strings.Contains(got, "HOST") || strings.Contains(got, "PTR.test") || strings.Contains(got, "SRV.test") {
			t.Errorf("domain fields not canonical: %q", got)
		}
		if rr.String() != before {
			t.Fatal("mutated original record")
		}
	}
}

func TestNegativeAndErrorPrecedence(t *testing.T) {
	nx1 := testdns.Start(t, testdns.Reply(dns.RcodeNameError))
	nx2 := testdns.Start(t, testdns.Reply(dns.RcodeNameError))
	if r := Run(context.Background(), config(nx1, nx2)); r.Status != "agree" {
		t.Fatalf("NXDOMAIN should agree: %+v", r)
	}
	empty := testdns.Start(t, testdns.Reply(0))
	fail := testdns.Start(t, testdns.Reply(dns.RcodeServerFailure))
	r := Run(context.Background(), config(nx1, empty, fail))
	if r.Status != "error" || r.Results[0].Group != 1 || r.Results[1].Group != 2 || r.Results[2].Group != 0 {
		t.Fatalf("error precedence/groups: %+v", r)
	}
}

func TestTCPFallback(t *testing.T) {
	server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if _, udp := w.LocalAddr().(*net.UDPAddr); udp {
			m := new(dns.Msg)
			m.SetReply(q)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		testdns.Reply(0, "example.test. 10 IN A 192.0.2.1")(w, q)
	})
	cfg := config(server)
	for _, directTCP := range []bool{false, true} {
		cfg.TCP = directTCP
		r := Run(context.Background(), cfg)
		if r.Status != "agree" || r.Results[0].Transport != "tcp" || len(r.Results[0].Answers) != 1 {
			t.Fatalf("TCP fallback/direct failed: %+v", r)
		}
	}
}

func TestInvalidResponses(t *testing.T) {
	for name, mutate := range map[string]func(*dns.Msg){
		"response bit":   func(m *dns.Msg) { m.Response = false },
		"opcode":         func(m *dns.Msg) { m.Opcode = dns.OpcodeStatus },
		"question count": func(m *dns.Msg) { m.Question = nil },
		"question name":  func(m *dns.Msg) { m.Question[0].Name = "wrong.test." },
		"question type":  func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA },
		"question class": func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS },
		"transaction ID": func(m *dns.Msg) { m.Id++ },
		"truncated TCP":  func(m *dns.Msg) { m.Truncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(q)
				mutate(m)
				_ = w.WriteMsg(m)
			})
			cfg := config(server)
			cfg.TCP = true
			r := Run(context.Background(), cfg)
			if r.Status != "error" {
				t.Fatalf("accepted invalid reply: %+v", r)
			}
		})
	}
}

func TestReferral(t *testing.T) {
	for _, soa := range []bool{false, true} {
		server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(q)
			rr, _ := dns.NewRR("test. 10 IN NS ns.test.")
			m.Ns = []dns.RR{rr}
			if soa {
				rr, _ = dns.NewRR("test. 10 IN SOA ns.test. hostmaster.test. 1 2 3 4 5")
				m.Ns = append(m.Ns, rr)
			}
			_ = w.WriteMsg(m)
		})
		r := Run(context.Background(), config(server))
		if (r.Status == "agree") != soa {
			t.Fatalf("referral detection with SOA=%v: %+v", soa, r)
		}
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {})
	cfg := config(server)
	cfg.Timeout = 40 * time.Millisecond
	start := time.Now()
	r := Run(context.Background(), cfg)
	if r.Status != "error" || time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = Run(ctx, config(server))
	if r.Status != "error" || !strings.Contains(r.Results[0].Error, "canceled") {
		t.Fatalf("cancellation not reported: %+v", r)
	}
}

func TestRecursionAndEDNS(t *testing.T) {
	for _, recurse := range []bool{false, true} {
		observed := make(chan *dns.Msg, 1)
		server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {
			observed <- q.Copy()
			testdns.Reply(0)(w, q)
		})
		cfg := config(server)
		cfg.Recurse = recurse
		Run(context.Background(), cfg)
		q := <-observed
		if q.RecursionDesired != recurse || q.IsEdns0() == nil || q.IsEdns0().UDPSize() != 1232 || q.IsEdns0().Do() {
			t.Fatalf("unexpected query: %+v", q)
		}
	}
}

func TestStableResults(t *testing.T) {
	left := testdns.Start(t, testdns.Reply(0, "example.test. 10 IN A 192.0.2.1"))
	right := testdns.Start(t, testdns.Reply(0, "example.test. 30 IN A 192.0.2.2"))
	cfg := config(left, right)
	first := Run(context.Background(), cfg)
	for range 5 {
		if got := Run(context.Background(), cfg); !reflect.DeepEqual(first, got) {
			t.Fatalf("results changed: first %+v, got %+v", first, got)
		}
	}
}

func TestCancellationDuringRead(t *testing.T) {
	started := make(chan struct{})
	server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) { close(started) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Report, 1)
	go func() { done <- Run(ctx, config(server)) }()
	<-started
	cancel()
	select {
	case r := <-done:
		if r.Status != "error" || !strings.Contains(r.Results[0].Error, "canceled") {
			t.Fatalf("cancellation not reported: %+v", r)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("in-flight read was not canceled")
	}
}

func TestFallbackSharesDeadline(t *testing.T) {
	server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if _, udp := w.LocalAddr().(*net.UDPAddr); udp {
			time.Sleep(80 * time.Millisecond)
			m := new(dns.Msg)
			m.SetReply(q)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		time.Sleep(80 * time.Millisecond)
		testdns.Reply(0)(w, q)
	})
	cfg := config(server)
	cfg.Timeout = 120 * time.Millisecond
	r := Run(context.Background(), cfg)
	if r.Status != "error" || r.Results[0].Transport != "tcp" {
		t.Fatalf("fallback restarted timeout budget: %+v", r)
	}
}

func TestPositiveAnswerWithNSAuthority(t *testing.T) {
	server := testdns.Start(t, func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		a, _ := dns.NewRR("example.test. 10 IN A 192.0.2.1")
		ns, _ := dns.NewRR("test. 10 IN NS ns.test.")
		m.Answer = []dns.RR{a}
		m.Ns = []dns.RR{ns}
		_ = w.WriteMsg(m)
	})
	if r := Run(context.Background(), config(server)); r.Status != "agree" {
		t.Fatalf("positive answer was mistaken for referral: %+v", r)
	}
}

func TestIPv6Transport(t *testing.T) {
	server := testdns.StartIPv6(t, testdns.Reply(0, "example.test. 60 IN AAAA 2001:db8::1"))
	cfg := config(server)
	cfg.Type = dns.TypeAAAA
	for _, tcp := range []bool{false, true} {
		cfg.TCP = tcp
		r := Run(context.Background(), cfg)
		if r.Status != "agree" || len(r.Results[0].Answers) != 1 {
			t.Fatalf("IPv6 query failed (TCP=%v): %+v", tcp, r)
		}
	}
}
