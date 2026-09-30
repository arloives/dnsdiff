package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/arloives/dnsdiff/internal/diff"
	"github.com/arloives/dnsdiff/internal/testdns"
	"github.com/miekg/dns"
)

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		{}, {"example.test"}, {"-r", "1.1.1.1", "example.test"},
		{"-r", "dns.test", "example.test"},
		{"-r", "1.1.1.1", "-r", "1.1.1.1:53", "example.test"},
		{"-r", "1.1.1.1", "-r", "8.8.8.8", "-type", "AXFR", "example.test"},
		{"-r", "1.1.1.1", "-r", "8.8.8.8", "-timeout", "0s", "example.test"},
		{"-r", "1.1.1.1", "-r", "8.8.8.8", "-timeout", "2m", "example.test"},
		{"-r", "1.1.1.1", "-r", "8.8.8.8", "example.test", "-json"},
		{"-r", "1.1.1.1", "-r", "8.8.8.8", "bad..name"},
		{"-unknown"},
	} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, &out, &errOut, "test"); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("args %v: code %d, stdout %q, stderr %q", args, code, out.String(), errOut.String())
		}
	}
}

func TestResolverLimit(t *testing.T) {
	var r resolvers
	for i := range diff.MaxResolvers {
		if err := r.Set("127.0.0.1:" + string(rune('A'+i))); err == nil {
			t.Fatal("accepted nonnumeric port")
		}
	}
	r = make(resolvers, diff.MaxResolvers)
	if err := r.Set("127.0.0.1:53"); err == nil {
		t.Fatal("accepted seventeenth resolver")
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-version"}} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, &out, &errOut, "v0.1.0"); code != 0 {
			t.Fatal(code)
		}
		if args[0] == "-version" && out.String() != "dnsdiff v0.1.0\n" {
			t.Fatal(out.String())
		}
	}
}

func TestCLIExitAndJSON(t *testing.T) {
	left := testdns.Start(t, testdns.Reply(0, "example.test. 1 IN A 192.0.2.1"))
	for _, tt := range []struct {
		rcode  int
		rr     string
		code   int
		status string
	}{
		{0, "example.test. 99 IN A 192.0.2.1", 0, "agree"},
		{0, "example.test. 1 IN A 192.0.2.2", 1, "differ"},
		{dns.RcodeServerFailure, "", 2, "error"},
	} {
		records := []string{}
		if tt.rr != "" {
			records = append(records, tt.rr)
		}
		right := testdns.Start(t, testdns.Reply(tt.rcode, records...))
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"-r", left, "-r", right, "-json", "EXAMPLE.test"}, &out, &errOut, "test")
		var report diff.Report
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err, out.String())
		}
		if code != tt.code || report.Status != tt.status || errOut.Len() != 0 || report.Name != "example.test." {
			t.Fatalf("code %d, report %+v, stderr %q", code, report, errOut.String())
		}
		for _, result := range report.Results {
			if result.Answers == nil {
				t.Fatal("JSON answers must be an array")
			}
		}
	}
}

func TestText(t *testing.T) {
	report := diff.Report{Name: "example.test.", Type: "A", Status: "differ", Results: []diff.Result{
		{Resolver: "127.0.0.1:5301", Transport: "udp", Rcode: "NOERROR", Group: 1, Answers: []string{"example.test.\tIN\tA\t192.0.2.1"}},
		{Resolver: "127.0.0.1:5302", Transport: "tcp", Rcode: "NXDOMAIN", Group: 2, Answers: []string{}},
	}}
	want := "example.test. A: differ\n\n127.0.0.1:5301 (udp): NOERROR, group 1\n  example.test.\tIN\tA\t192.0.2.1\n\n127.0.0.1:5302 (tcp): NXDOMAIN, group 2\n  (empty answer section)\n"
	if got := text(report); got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
	if got := safeText("safe\x1b[31m\n\r\x7f"); got != `safe\x1b[31m\x0a\x0d\x7f` {
		t.Fatal(got)
	}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errors.New("broken writer") }

func TestOutputFailure(t *testing.T) {
	left := testdns.Start(t, testdns.Reply(0))
	right := testdns.Start(t, testdns.Reply(0))
	for _, jsonFlag := range []string{"-json=true", "-json=false"} {
		var errOut bytes.Buffer
		code := Run(context.Background(), []string{"-r", left, "-r", right, jsonFlag, "example.test"}, failingWriter{}, &errOut, "test")
		if code != 2 || !strings.Contains(errOut.String(), "write output") {
			t.Fatal(code, errOut.String())
		}
	}
}
