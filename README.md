# ct-disco

**Certificate Transparency Log domain discovery**

ct-disco queries [Certificate Transparency](https://certificate.transparency.dev/) (CT) logs directly to find hostnames containing a keyword. Every TLS certificate issued by a public CA must be logged in a CT log before browsers will trust it, which makes CT logs a near-real-time feed of new hostnames on the internet.

## What it does

1. Connects to one or more CT log endpoints (Google Xenon2026h1 by default).
2. Queries the log's Signed Tree Head (`get-sth`) to learn the true tree size, then picks a **random start index** within that range.
3. Fetches batches of raw certificate entries (`get-entries`).
4. Decodes each `leaf_input` field (base64-encoded DER certificate data).
5. Extracts all hostnames using a two-phase approach: broad regex + O(1) lookup against the full IANA TLD list.
6. Prints any hostname that contains the keyword.

Typical use cases:
- **Domain takeover hunting** — spot subdomains pointing at decommissioned cloud resources before attackers do.
- **Brand / asset monitoring** — track new certificates issued for names that contain your organisation's keyword.
- **Shadow IT discovery** — surface hostnames being registered outside your known inventory.

## Requirements

```
pip install requests
```

Python 3.8+.

## Usage

```
python ct-disco.py [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-k` / `--keyword` | `skyscanner` | Keyword to search for in hostnames |
| `--start` | random | Starting entry index (single-log mode only; overrides the randomised value) |
| `--max` | `1000` | Maximum entries to scan **per log** |
| `--batch-size` | `1000` | Entries fetched per API request |
| `--rate-limit` | `0.5` | Seconds to wait between requests, per log thread |
| `--operator-concurrency` | `1` | Max simultaneous in-flight requests to the same CT operator (prevents hammering a single server when scanning multiple logs from the same provider) |
| `--log` | `google/xenon2026h1` | CT log(s) to query: a single alias, a comma-separated list, `all`, or a full `get-entries` URL |
| `--list-logs` | — | Print all built-in CT log aliases and exit |
| `-v` / `--verbose` | off | Print every hostname seen, diagnostic info, and per-log start positions |

### Examples

Search for your brand across 5 000 random entries in the default log:

```
python ct-disco.py -k mycompany --max 5000
```

Start from a known index with verbose output:

```
python ct-disco.py -k mycompany --start 50000000 -v
```

Scan multiple logs in parallel (Google EU + Cloudflare):

```
python ct-disco.py -k mycompany --log google/xenon2026h1,cloudflare/nimbus2026
```

Scan all 28 known logs at once:

```
python ct-disco.py -k mycompany --log all --max 2000
```

Point at a custom CT log endpoint:

```
python ct-disco.py -k mycompany \
  --log https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1/get-entries
```

List all built-in log aliases:

```
python ct-disco.py --list-logs
```

### Output

Single-log run:

```
++ Querying CTL logs directly
++ Keyword:    mycompany
++ Logs:       1 (google/xenon2026h1)
++ Max/log:    1000
++ Rate limit: 0.5s/request per log  |  max 1 concurrent request(s) per operator
++ Fetching tree sizes...
++ Tree size:    2,134,567,890
++ Start index:  847,291,004 (randomized)
++ Starting scan...
.......
--> api.mycompany.io
......
--> staging.mycompany.com
...
[1,000 scanned | 5s elapsed | ~196/s]
--EOF
Scanned 1,000 entries across 1 log(s) in 5.1s  (~196 entries/s)
```

Multi-log run (`--log all`):

```
++ Querying CTL logs directly
++ Keyword:    mycompany
++ Logs:       28 (all known)
++ Max/log:    1000
++ Rate limit: 0.5s/request per log  |  max 1 concurrent request(s) per operator
++ Fetching tree sizes...
   google/xenon2026h1               size=2,134,567,890   start=847,291,004 (randomized)
   cloudflare/nimbus2026            size=980,123,456     start=312,005,100 (randomized)
   ...
++ Starting scan...
.......
--> [google/xenon2026h1] api.mycompany.io
...
[1,000 scanned | 6s elapsed | ~167/s]
```

Each `.` is one certificate processed without a match. The `[N scanned | …]` line is printed every 1 000 entries as a heartbeat. Matching hostnames are printed immediately prefixed with `-->` (and `[log-alias]` when scanning multiple logs).

## How CT logs work

Every certificate trusted by major browsers must be submitted to at least two CT logs. Each log is an append-only Merkle tree where entries are addressable by integer index. The `get-entries` API returns the raw `leaf_input` for each entry — a base64-encoded TLS certificate in DER format.

ct-disco decodes each entry and uses regex to extract hostnames from the binary certificate data. Because DER encoding places the ASN.1 SEQUENCE tag byte (`\x30`, ASCII `0`) immediately after domain strings, the hostname pattern uses `(?![a-z-])` as a negative lookahead (rather than `(?![a-z0-9-])`) so that trailing binary bytes do not silently suppress matches.

### Rate limiting and multi-log safety

By default ct-disco waits **0.5 s between requests per log thread** and allows at most **1 concurrent request per CT operator** (e.g. all `google/*` logs share one in-flight slot). This means that even with `--log all` (28 logs across ~5 operators), each operator receives at most 2 req/s — well within public CT API limits.

To scan faster at the cost of higher server load, you can lower `--rate-limit` and/or raise `--operator-concurrency`, but the conservative defaults are intentional.

## Running the tests

```
python -m pytest test_ct_disco.py -v
```

The test suite includes:

- **Unit tests** (no network) — domain parsing, TLD validation, IP-like domain rejection, the DER `\x30` byte regression, and a hardcoded real CT entry (Xenon2025h2, index 100).
- **Integration tests** (skipped if the CTL API is unreachable) — fetch live entries and verify specific domains are extracted, including `.click` gTLD and multi-label AWS subdomains.

## Author

ramon.pinuaga@skyscanner.net
