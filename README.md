# dnsdiff

[![CI](https://github.com/arloives/dnsdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/arloives/dnsdiff/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/arloives/dnsdiff.svg)](https://pkg.go.dev/github.com/arloives/dnsdiff)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Compare DNS answers across resolvers before, during, and after a migration.**

`dnsdiff` asks the same question of the servers you choose, groups matching answers, and exits nonzero when they differ. A small Go CLI with readable output, JSON for scripts, and no configured public resolver defaults.

- Compare A, AAAA, CAA, CNAME, DNAME, MX, NS, PTR, SOA, SRV, and TXT records
- Ignore answer order, duplicates, and cache TTL differences
- Keep aliases, owner names, TXT case and string boundaries, and meaningful RDATA
- Query IPv4 or IPv6 endpoints concurrently, with a bounded deadline
- Retry truncated UDP replies over TCP; optionally use TCP from the start
- Distinguish answer differences from timeouts, failures, and malformed replies

## Install

Requires **Go 1.25 or later**:

```sh
go install github.com/arloives/dnsdiff@latest
```

This installs the `dnsdiff` binary into `$(go env GOPATH)/bin` unless `GOBIN` is set. Add that directory to your `PATH` if needed. Go is needed to build/install; the resulting binary runs on its own.

Or build a checkout:

```sh
git clone https://github.com/arloives/dnsdiff.git
cd dnsdiff
go build -o bin/dnsdiff .
./bin/dnsdiff -h
```

## Quick start

Compare two public recursive resolvers (this sends the queried name to both providers):

```sh
dnsdiff -r 1.1.1.1 -r 8.8.8.8 example.com
```

Check mail records or get JSON:

```sh
dnsdiff -r 1.1.1.1 -r 8.8.8.8 -type MX example.com
dnsdiff -r 1.1.1.1 -r 8.8.8.8 -type TXT -json example.com
```

Use your own DNS servers, custom ports, or IPv6:

```sh
dnsdiff -r 192.0.2.10 -r 192.0.2.20 -recurse=false example.com
dnsdiff -r 127.0.0.1:5301 -r '[::1]:5302' -tcp -timeout 2s example.test
```

The last two examples use documentation or loopback addresses: substitute your running servers. For PTR, pass the reverse DNS name, such as `1.2.0.192.in-addr.arpa`.

All flags go **before** the name. Repeat `-r` for 2–16 distinct endpoints. Resolver hostnames are intentionally rejected, so no implicit system resolver is used to look them up. Use ASCII/punycode DNS names for IDNs.

### Example output

Illustrative output from two local servers with different records:

```text
example.test. A: differ

127.0.0.1:5301 (udp): NOERROR, group 1
  example.test.  IN  A  192.0.2.10

127.0.0.1:5302 (udp): NOERROR, group 2
  example.test.  IN  A  192.0.2.20
```

Resolvers in the same group returned the same normalized answer set and response code. Group numbers follow resolver input order; there is no majority winner or claim that one answer is correct.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every query completed, and all results agree |
| `1` | Every query completed, but results differ |
| `2` | Invalid arguments, query/cancellation failure, unsupported reply, or output error |

An error takes precedence over a difference. Successful results still appear beside failures. `NXDOMAIN` is a comparable DNS result: two matching NXDOMAIN replies exit `0`. Agreement is **not** a check that the name exists or has any records.

`go run` wraps program failures; build or install the binary when consuming these exact exit codes.

### JSON

`-json` writes one object to stdout, including operational errors. Usage errors go to stderr. Results preserve the order of `-r` arguments, and answers are sorted. There are no timestamps or latency values to create noisy diffs.

```json
{
  "name": "example.test.",
  "type": "A",
  "status": "differ",
  "results": [
    {
      "resolver": "127.0.0.1:5301",
      "transport": "udp",
      "rcode": "NOERROR",
      "answers": ["example.test.\tIN\tA\t192.0.2.10"],
      "group": 1
    },
    {
      "resolver": "127.0.0.1:5302",
      "transport": "udp",
      "rcode": "NOERROR",
      "answers": ["example.test.\tIN\tA\t192.0.2.20"],
      "group": 2
    }
  ]
}
```

Failed results have `error` and omit `group`; `rcode` is present only if a validated response was received. `answers` is always an array. The top-level `status` is `agree`, `differ`, or `error`. Transport shows the final attempted protocol, including a failed TCP fallback. Error text can vary by OS; script against status, exit codes, and the presence of `error`.

## What is compared?

The DNS response code and **entire supported answer section**, including any received CNAME/DNAME chain. Records are compared as sets, with their owner names, classes, types, and data:

- Domain names are normalized for ASCII case and escaped presentation spelling
- CAA tags are case-insensitive; CAA values and TXT bytes remain case-sensitive
- TXT string boundaries are preserved
- Only the RR header TTL is ignored; SOA serial, timers, and minimum remain data
- Authority/additional records, DNS flags, latency, and header TTLs are not compared

This is a comparison of observed answers from one network location at one moment. It does **not** prove global DNS propagation, zone parity, DNS correctness, or that a migration is finished. Geo-routing, split-horizon DNS, load balancing, caches, and different policies can produce legitimate differences. Multiple IPs may reach the same underlying resolver infrastructure.

Queries use class IN and request recursion by default. `-recurse=false` is useful when directly querying authoritative servers; the tool does not follow referrals or chase aliases beyond the answer it receives. Obvious empty, non-authoritative referrals (NS authority records without SOA) are errors. Empty NOERROR answers are reported as empty, without assuming their cause.

There is no zone enumeration/AXFR, DNSSEC validation, DoH, DoT, EDNS Client Subnet, automatic retries after timeouts, watch mode, or automatic IDNA conversion. Unknown answer record types are errors rather than silently discarded. DNSSEC signatures included unsolicited in an answer are therefore unsupported.

## Timeouts and privacy

`-timeout` is a per-resolver budget, including UDP and any TCP fallback; it defaults to `3s` and is limited to `1m`. Up to 16 selected servers are queried concurrently. UDP advertises an EDNS payload of 1232 bytes, and TCP DNS messages are bounded by the protocol's 65,535-byte length field. Truncated TCP responses and mismatched questions are rejected.

Only the endpoints you explicitly pass are queried. DNS traffic is unencrypted; the chosen servers and network observers can see queried names. There is no telemetry, account, API key, or background service.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./...
test -z "$(gofmt -l .)"
```

Tests use deterministic local UDP/TCP DNS servers. They do not query public DNS or require external services after module download. The only direct dependency is [miekg/dns](https://github.com/miekg/dns), used for DNS wire encoding, parsing, and transport rather than a hand-written protocol implementation. Its transitive modules are pinned in `go.mod`/`go.sum`.

Bug reports should include the command, version, OS, expected/actual results, and a redacted response if appropriate. Avoid publishing private domains, internal IPs, or sensitive TXT records. Keep changes small and include a local fixture for protocol behavior changes.

## Background

This is Arlo Ives's independent Go project. Other tools share the name, including [joshenders/dnsdiff](https://github.com/joshenders/dnsdiff); this repository is not affiliated with them.

Protocol references: [DNS case insensitivity](https://www.rfc-editor.org/rfc/rfc4343), [RRsets and TTLs](https://www.rfc-editor.org/rfc/rfc2181), [negative responses](https://www.rfc-editor.org/rfc/rfc2308), [TCP fallback](https://www.rfc-editor.org/rfc/rfc7766), and [CAA tags](https://www.rfc-editor.org/rfc/rfc8659).

## License

[MIT](LICENSE) © 2026 Arlo Ives
