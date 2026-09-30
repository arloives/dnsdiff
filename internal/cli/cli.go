// Package cli implements the command-line interface without process exits.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/arloives/dnsdiff/internal/diff"
)

type resolvers []string

func (r *resolvers) String() string { return strings.Join(*r, ", ") }
func (r *resolvers) Set(s string) error {
	if len(*r) >= diff.MaxResolvers {
		return fmt.Errorf("at most %d resolvers are allowed", diff.MaxResolvers)
	}
	value, err := diff.Resolver(s)
	if err != nil {
		return err
	}
	for _, existing := range *r {
		if existing == value {
			return fmt.Errorf("duplicate resolver %q", value)
		}
	}
	*r = append(*r, value)
	return nil
}

// Run returns 0 for agreement, 1 for disagreement, and 2 for usage, query,
// cancellation or output errors. Error takes precedence over disagreement.
func Run(ctx context.Context, args []string, out, errOut io.Writer, version string) int {
	fs := flag.NewFlagSet("dnsdiff", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var rs resolvers
	fs.Var(&rs, "r", "resolver IP or IP:port; repeat 2–16 times (IPv6 ports need brackets)")
	typeName := fs.String("type", "A", "record type: A AAAA CAA CNAME DNAME MX NS PTR SOA SRV TXT")
	timeout := fs.Duration("timeout", 3*time.Second, "per-resolver deadline including TCP fallback (max 1m)")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	tcp := fs.Bool("tcp", false, "query over TCP directly")
	recurse := fs.Bool("recurse", true, "request recursion; set false for authoritative servers")
	showVersion := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "Usage: dnsdiff [flags] name\n\nCompare one DNS question across explicit resolvers. Put flags before name.")
		fs.PrintDefaults()
		fmt.Fprintln(errOut, "\nExit codes: 0 agree, 1 differ, 2 error. TTLs and record order are ignored.")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		if _, err := fmt.Fprintln(out, "dnsdiff "+version); err != nil {
			return 2
		}
		return 0
	}
	usageError := func(format string, values ...any) int {
		fmt.Fprintf(errOut, "dnsdiff: "+format+"\n", values...)
		return 2
	}
	if fs.NArg() != 1 {
		return usageError("provide exactly one DNS name; put all flags before it (see -h)")
	}
	if len(rs) < 2 {
		return usageError("provide at least two distinct resolvers with -r")
	}
	if *timeout <= 0 || *timeout > time.Minute {
		return usageError("timeout must be greater than zero and at most 1m")
	}
	qtype, ok := diff.Types[strings.ToUpper(*typeName)]
	if !ok {
		return usageError("unsupported record type %q (see -h)", *typeName)
	}
	name, err := diff.Name(fs.Arg(0))
	if err != nil {
		return usageError("%s", err)
	}
	report := diff.Run(ctx, diff.Config{Name: name, Type: qtype, Resolvers: rs, Timeout: *timeout, TCP: *tcp, Recurse: *recurse})
	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
	} else {
		_, err = io.WriteString(out, text(report))
	}
	if err != nil {
		fmt.Fprintf(errOut, "dnsdiff: write output: %v\n", err)
		return 2
	}
	switch report.Status {
	case "agree":
		return 0
	case "differ":
		return 1
	default:
		return 2
	}
}

func text(report diff.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: %s\n", report.Name, report.Type, report.Status)
	for _, r := range report.Results {
		if r.Error != "" {
			fmt.Fprintf(&b, "\n%s (%s): ERROR %s\n", r.Resolver, r.Transport, safeText(r.Error))
			continue
		}
		fmt.Fprintf(&b, "\n%s (%s): %s, group %d\n", r.Resolver, r.Transport, r.Rcode, r.Group)
		if len(r.Answers) == 0 {
			b.WriteString("  (empty answer section)\n")
		}
		for _, answer := range r.Answers {
			fmt.Fprintf(&b, "  %s\n", safeText(answer))
		}
	}
	return b.String()
}

// Do not let DNS-controlled values inject terminal control sequences.
func safeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r < 32 && r != '\t') || r == 127 || (r >= 128 && r <= 159) {
			fmt.Fprintf(&b, "\\x%02x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
