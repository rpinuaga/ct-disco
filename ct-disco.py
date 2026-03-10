#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ct-disco - Certificate Transparency Log domain discovery

import sys
import time
import argparse
import re
import base64
import random
import importlib.util
import concurrent.futures
import threading
import queue
from pathlib import Path

import requests

# Load tlds.py by path so this script works regardless of sys.path / working
# directory (the filename "ct-disco.py" is not a valid module identifier, so
# normal relative imports are unavailable).
_tlds_spec = importlib.util.spec_from_file_location(
    "tlds", Path(__file__).with_name("tlds.py")
)
_tlds_mod = importlib.util.module_from_spec(_tlds_spec)
_tlds_spec.loader.exec_module(_tlds_mod)
VALID_TLDS = _tlds_mod.VALID_TLDS

DEFAULT_MAX = 1000
DEFAULT_BATCH_SIZE = 1000
DEFAULT_RATE_LIMIT_DELAY = 0.5   # seconds between requests, per log thread
DEFAULT_OPERATOR_CONCURRENCY = 3  # max simultaneous in-flight requests per operator
STH_TIMEOUT = 1.5          # seconds — STH probe hard deadline
STH_PROBE_WORKERS = 10     # parallel STH probes; enough to be fast without thundering-herd

# Verified-working CT logs (RFC 6962 get-entries API).
# Tested: curl "<base>ct/v1/get-entries?start=0&end=0"  → HTTP 200 with entries.
# Logs using the newer Sunlight protocol (Geomys, IPng, Let's Encrypt Oak/Willow)
# are intentionally excluded — they expose a different API.
# Source: https://www.gstatic.com/ct/log_list/v3/log_list.json
KNOWN_LOGS = {
    # Google — EU
    "google/xenon2025h2": "https://ct.googleapis.com/logs/eu1/xenon2025h2/ct/v1/get-entries",
    "google/xenon2026h1": "https://ct.googleapis.com/logs/eu1/xenon2026h1/ct/v1/get-entries",
    "google/xenon2026h2": "https://ct.googleapis.com/logs/eu1/xenon2026h2/ct/v1/get-entries",
    "google/xenon2027h1": "https://ct.googleapis.com/logs/eu1/xenon2027h1/ct/v1/get-entries",
    # Google — US
    "google/argon2026h1": "https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1/get-entries",
    "google/argon2026h2": "https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1/get-entries",
    "google/argon2027h1": "https://ct.googleapis.com/logs/us1/argon2027h1/ct/v1/get-entries",
    # Cloudflare
    "cloudflare/nimbus2026": "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-entries",
    "cloudflare/nimbus2027": "https://ct.cloudflare.com/logs/nimbus2027/ct/v1/get-entries",
    # DigiCert — Wyvern
    "digicert/wyvern2026h1": "https://wyvern.ct.digicert.com/2026h1/ct/v1/get-entries",
    "digicert/wyvern2026h2": "https://wyvern.ct.digicert.com/2026h2/ct/v1/get-entries",
    "digicert/wyvern2027h1": "https://wyvern.ct.digicert.com/2027h1/ct/v1/get-entries",
    "digicert/wyvern2027h2": "https://wyvern.ct.digicert.com/2027h2/ct/v1/get-entries",
    # DigiCert — Sphinx
    "digicert/sphinx2026h1": "https://sphinx.ct.digicert.com/2026h1/ct/v1/get-entries",
    "digicert/sphinx2026h2": "https://sphinx.ct.digicert.com/2026h2/ct/v1/get-entries",
    "digicert/sphinx2027h1": "https://sphinx.ct.digicert.com/2027h1/ct/v1/get-entries",
    "digicert/sphinx2027h2": "https://sphinx.ct.digicert.com/2027h2/ct/v1/get-entries",
    # Sectigo — Elephant
    "sectigo/elephant2026h1": "https://elephant2026h1.ct.sectigo.com/ct/v1/get-entries",
    "sectigo/elephant2026h2": "https://elephant2026h2.ct.sectigo.com/ct/v1/get-entries",
    "sectigo/elephant2027h1": "https://elephant2027h1.ct.sectigo.com/ct/v1/get-entries",
    "sectigo/elephant2027h2": "https://elephant2027h2.ct.sectigo.com/ct/v1/get-entries",
    # Sectigo — Tiger
    "sectigo/tiger2026h1": "https://tiger2026h1.ct.sectigo.com/ct/v1/get-entries",
    "sectigo/tiger2026h2": "https://tiger2026h2.ct.sectigo.com/ct/v1/get-entries",
    "sectigo/tiger2027h1": "https://tiger2027h1.ct.sectigo.com/ct/v1/get-entries",
    "sectigo/tiger2027h2": "https://tiger2027h2.ct.sectigo.com/ct/v1/get-entries",
    # TrustAsia
    "trustasia/log2026a": "https://ct2026-a.trustasia.com/log2026a/ct/v1/get-entries",
    "trustasia/log2026b": "https://ct2026-b.trustasia.com/log2026b/ct/v1/get-entries",
    "trustasia/hetu2027": "https://hetu2027.trustasia.com/hetu2027/ct/v1/get-entries",
}

DEFAULT_LOG = "google/xenon2026h1"

# Pre-compiled broad pattern: matches any hostname-shaped string whose TLD is
# 2–18 letters long.  The TLD is captured in group 1 so we can validate it
# against VALID_TLDS without building a 1000-alternation regex.
# Max non-IDN TLD length in IANA list is 18 ('travelersinsurance').
_DOMAIN_RE = re.compile(
    r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,18})(?![a-z-])',
    re.IGNORECASE,
)


def extract_domains_from_binary(data):
    """Extract domain names from certificate binary data.

    Two-phase approach:
      1. Broad regex captures anything shaped like a hostname.
      2. The captured TLD is validated against the full IANA VALID_TLDS set (O(1)).

    The lookahead (?![a-z-]) allows a digit immediately after the TLD — DER-encoded
    certs place \\x30 (ASCII '0', the ASN.1 SEQUENCE tag) right after domain strings,
    which would otherwise silently drop valid matches.
    """
    domains = set()
    try:
        text = data.decode('utf-8', errors='ignore')
        for m in _DOMAIN_RE.finditer(text):
            tld = m.group(1).lower()
            if tld not in VALID_TLDS:
                continue
            domain = m.group(0).lower()
            if len(domain) <= 3 or domain.count('.') < 1:
                continue
            # The label immediately before the TLD must contain at least one
            # letter — all-digit labels indicate IP-address-like garbage
            # (e.g. "000.000.000.co").
            parts = domain.split('.')
            if re.search(r'[a-z]', parts[-2]):
                domains.add(domain)
    except Exception:
        pass
    return list(domains)


def query_ctl_log(log_url, start_index, batch_size, verbose=False):
    """Query a CTL log endpoint for a batch of certificate entries."""
    url = f"{log_url}?start={start_index}&end={start_index + batch_size - 1}"
    if verbose:
        sys.stdout.write(f"[query] {url}\n")
        sys.stdout.flush()
    try:
        response = requests.get(url, timeout=3)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code
        if code == 404:
            return None   # log doesn't have these entries yet; stop quietly
        elif code == 503:
            return None
        elif verbose:
            sys.stdout.write(f"[error] HTTP {code}: {e}\n")
            sys.stdout.flush()
        return None
    except requests.exceptions.Timeout:
        if verbose:
            sys.stdout.write("[error] Read timeout\n")
            sys.stdout.flush()
        return None
    except Exception as e:
        if verbose:
            sys.stdout.write(f"[error] Query failed: {e}\n")
            sys.stdout.flush()
        return None


def get_tree_size(log_url):
    """Return (tree_size, elapsed_s).  tree_size is None if the probe fails or times out."""
    sth_url = log_url.replace("ct/v1/get-entries", "ct/v1/get-sth")
    t0 = time.time()
    try:
        response = requests.get(sth_url, timeout=STH_TIMEOUT)
        elapsed = time.time() - t0
        response.raise_for_status()
        size = response.json().get("tree_size", 0)
        if size > 0:
            return size, elapsed
    except Exception:
        pass
    return None, time.time() - t0





def _operator(label):
    """Return the operator portion of a log label (e.g. 'google' from 'google/xenon2026h1').
    Raw URLs are used as their own operator key."""
    return label.split('/')[0] if '/' in label else label


def _build_operator_semaphores(logs, concurrency):
    """Return a dict mapping operator name → threading.Semaphore(concurrency)."""
    operators = {_operator(label) for label, _ in logs}
    return {op: threading.Semaphore(concurrency) for op in operators}


def _resolve_logs(log_arg):
    """Parse --log value into a list of (label, url) tuples.

    Accepts:
      - "all"                        → all KNOWN_LOGS
      - "google/xenon2026h1"         → single alias
      - "alias1,alias2,..."          → comma-separated aliases
      - "https://..."                → raw URL (used as both label and URL)
    """
    if log_arg == "all":
        return list(KNOWN_LOGS.items())

    logs = []
    for token in log_arg.split(","):
        token = token.strip()
        if token in KNOWN_LOGS:
            logs.append((token, KNOWN_LOGS[token]))
        elif token.startswith("http"):
            logs.append((token, token))
        else:
            sys.stderr.write(
                f"Unknown log '{token}'. Use --list-logs to see options, "
                "or pass a full URL.\n"
            )
            sys.exit(2)
    return logs


def _scan_worker(log_url, log_label, keyword, start_index, max_entries,
                 batch_size, rate_limit, operator_sem, out_queue, verbose):
    """Worker thread: scan one CTL log and push events to out_queue.

    operator_sem is a threading.Semaphore shared by all logs from the same
    operator.  Acquiring it before each HTTP request ensures at most
    --operator-concurrency requests are in-flight to that server at once.

    Events pushed as (kind, log_label, data):
      ('dot',   label, None)    — one certificate entry processed
      ('match', label, domain)  — keyword found in domain
      ('error', label, msg)     — non-fatal error (verbose only)
      ('done',  label, count)   — worker finished; count = entries scanned
    """
    cert_count = 0
    index = start_index
    try:
        while cert_count < max_entries:
            # Cap the request to exactly what we still need — avoids fetching
            # batch_size=1000 entries when --max 50 only needs 50.
            effective_batch = min(batch_size, max_entries - cert_count)
            with operator_sem:
                result = query_ctl_log(log_url, index, effective_batch, verbose)
            if result is None:
                break

            entries = result.get('entries', [])
            if not entries:
                break

            for entry in entries:
                if cert_count >= max_entries:
                    break
                # Count one per certificate entry, not per domain.
                cert_count += 1
                out_queue.put(('dot', log_label, None))
                try:
                    leaf = entry.get('leaf_input', '')
                    if leaf:
                        cert_data = base64.b64decode(leaf)
                        domains = extract_domains_from_binary(cert_data)
                        for domain in domains:
                            if keyword in domain:
                                out_queue.put(('match', log_label, domain))
                except Exception as exc:
                    if verbose:
                        out_queue.put(('error', log_label, str(exc)))

            index += effective_batch
            # Only sleep between batches — skip if this was the last one.
            if rate_limit > 0 and cert_count < max_entries:
                time.sleep(rate_limit)

    finally:
        out_queue.put(('done', log_label, cert_count))


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description='Certificate Transparency Log domain discovery — find hostnames by keyword.'
    )
    parser.add_argument(
        '-k', '--keyword', default='skyscanner',
        help='Keyword to search for in domains. Default: skyscanner',
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose diagnostics.')
    parser.add_argument(
        '--start', type=int, default=None,
        help='Starting entry index. Only used when scanning a single log; '
             'ignored when scanning multiple logs (each starts at a random position).',
    )
    parser.add_argument(
        '--max', type=int, default=DEFAULT_MAX,
        help=f'Max entries to scan *per log*. Default: {DEFAULT_MAX}',
    )
    parser.add_argument(
        '--batch-size', type=int, default=DEFAULT_BATCH_SIZE,
        help=f'Entries fetched per API request. Default: {DEFAULT_BATCH_SIZE}',
    )
    parser.add_argument(
        '--rate-limit', type=float, default=DEFAULT_RATE_LIMIT_DELAY,
        help=f'Seconds between requests per log thread. Default: {DEFAULT_RATE_LIMIT_DELAY}',
    )
    parser.add_argument(
        '--operator-concurrency', type=int, default=DEFAULT_OPERATOR_CONCURRENCY,
        help=(
            'Max simultaneous in-flight HTTP requests to the same CT operator. '
            'Prevents hammering a single server when scanning multiple logs from '
            f'the same provider (e.g. google/*). Default: {DEFAULT_OPERATOR_CONCURRENCY}'
        ),
    )
    parser.add_argument(
        '--log', default=DEFAULT_LOG,
        help=(
            'CT log(s) to query. Options: a single alias, a comma-separated list of '
            f'aliases, "all" (scan all {len(KNOWN_LOGS)} known logs in parallel), or a '
            'full get-entries URL. Default: %(default)s. '
            'See --list-logs for available aliases.'
        ),
    )
    parser.add_argument(
        '--list-logs', action='store_true',
        help='Print all built-in CT log aliases and exit.',
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.list_logs:
        width = max(len(k) for k in KNOWN_LOGS)
        for alias, url in sorted(KNOWN_LOGS.items()):
            marker = " (default)" if alias == DEFAULT_LOG else ""
            sys.stdout.write(f"  {alias:{width}}  {url}{marker}\n")
        sys.exit(0)

    if not re.match(r'^[\w.\-]+$', args.keyword):
        sys.stderr.write(
            f"Invalid keyword: '{args.keyword}'. "
            "Allowed characters: letters, digits, underscore, dot, hyphen.\n"
        )
        sys.exit(2)

    logs = _resolve_logs(args.log)
    keyword = args.keyword.lower()
    multi = len(logs) > 1

    # Build per-operator semaphores before printing so we can show the limits.
    op_sems = _build_operator_semaphores(logs, args.operator_concurrency)

    sys.stdout.write("++ Querying CTL logs directly\n")
    sys.stdout.write(f"++ Keyword:    {args.keyword}\n")
    sys.stdout.write(f"++ Logs:       {len(logs)} ({'all known' if args.log == 'all' else ', '.join(l for l, _ in logs)})\n")
    sys.stdout.write(f"++ Max/log:    {args.max}\n")
    sys.stdout.write(f"++ Rate limit: {args.rate_limit}s/request per log  |  "
                     f"max {args.operator_concurrency} concurrent request(s) per operator\n")
    if args.verbose:
        sys.stdout.write(f"++ Operators:  {', '.join(sorted(op_sems))}\n")
        sys.stdout.write(f"++ Batch:      {args.batch_size}\n")
    sys.stdout.flush()

    # Determine start indices.  STH fetches are subject to the same per-operator
    # semaphores as the scan workers, so we never fire concurrent requests at the
    # same operator even during startup.  Operators run in parallel with each other.
    # STH probes run at STH_PROBE_WORKERS concurrency — fast but avoids thundering herd
    # from firing all requests simultaneously.  Logs that don't reply within STH_TIMEOUT
    # are skipped; slow scan servers are caught later by the 3s scan request timeout.
    def _fetch_start(lbl, url):
        if not multi and args.start is not None:
            return lbl, args.start, None, None
        tree_size, elapsed = get_tree_size(url)
        if tree_size is None:
            return lbl, None, None, f"no STH response within {STH_TIMEOUT}s"
        idx = random.randint(0, max(0, tree_size - args.max))
        return lbl, idx, tree_size, elapsed

    sys.stdout.write(
        f"++ Probing {len(logs)} log(s) "
        f"({STH_PROBE_WORKERS} at a time, timeout {STH_TIMEOUT}s)...\n"
    )
    sys.stdout.flush()

    log_starts = {}
    if multi:
        with concurrent.futures.ThreadPoolExecutor(max_workers=STH_PROBE_WORKERS) as pool:
            futs = {pool.submit(_fetch_start, lbl, url): lbl for lbl, url in logs}
            for fut in concurrent.futures.as_completed(futs):
                lbl, idx, tree_size, result = fut.result()
                if isinstance(result, str):  # skip_reason string
                    sys.stdout.write(f"   {lbl:<34}  SKIPPED — {result}\n")
                    sys.stdout.flush()
                    continue
                log_starts[lbl] = idx
                elapsed = result  # float elapsed seconds
                sys.stdout.write(
                    f"   {lbl:<34}  size={tree_size:<16,}  start={idx:,}  ({elapsed:.2f}s)\n"
                )
                sys.stdout.flush()
    else:
        lbl, url = logs[0]
        _, idx, tree_size, result = _fetch_start(lbl, url)
        if isinstance(result, str):
            sys.stderr.write(f"Error: {lbl} — {result}.\nTry a different log (see --list-logs).\n")
            sys.exit(1)
        log_starts[lbl] = idx
        if args.start is not None:
            sys.stdout.write(f"++ Start index:  {idx:,} (fixed via --start)\n")
        else:
            sys.stdout.write(f"++ Tree size:    {tree_size:,}\n")
            sys.stdout.write(f"++ Start index:  {idx:,} (randomized)\n")
        sys.stdout.flush()

    # Dot density scales with --max so the terminal doesn't flood on large scans.
    # Each tier is one power of 10 more aggressive than the previous.
    if args.max > 100_000:
        dot_interval = 10_000
    elif args.max > 10_000:
        dot_interval = 1_000
    elif args.max > 1_000:
        dot_interval = 100
    elif args.max > 100:
        dot_interval = 10
    else:
        dot_interval = 1
    heartbeat_interval = 1_000 * dot_interval  # always fire after 1000 dots worth of entries

    # Launch one worker thread per responsive log (skipped logs have no entry in log_starts).
    skipped = len(logs) - len(log_starts)
    skip_note = f"  ({skipped} skipped — no STH response)" if skipped else ""
    dot_note = f"  (1 dot = {dot_interval:,} entries)" if dot_interval > 1 else ""
    sys.stdout.write(f"++ Starting scan across {len(log_starts)} log(s){skip_note}{dot_note}...\n")
    sys.stdout.flush()
    if not log_starts:
        sys.stderr.write("No logs responded. Try --list-logs or check your connection.\n")
        sys.exit(1)
    out_queue = queue.Queue()
    workers_launched = 0
    for label, url in logs:
        if label not in log_starts:
            continue
        t = threading.Thread(
            target=_scan_worker,
            args=(url, label, keyword, log_starts[label], args.max,
                  args.batch_size, args.rate_limit,
                  op_sems[_operator(label)], out_queue, args.verbose),
            daemon=True,
        )
        t.start()
        workers_launched += 1

    # Main thread: drain the queue and handle all output.
    printed_domains = set()
    total_scanned = 0
    done_count = 0
    start_time = time.time()

    try:
        while done_count < workers_launched:
            kind, label, data = out_queue.get()

            if kind == 'dot':
                total_scanned += 1
                if total_scanned % dot_interval == 0:
                    sys.stdout.write('.')
                if total_scanned % heartbeat_interval == 0:
                    elapsed = time.time() - start_time
                    rate = int(total_scanned / elapsed) if elapsed > 0 else 0
                    sys.stdout.write(
                        f"\n[{total_scanned:,} scanned | {elapsed:.0f}s elapsed | ~{rate:,}/s]\n"
                    )
                sys.stdout.flush()

            elif kind == 'match':
                if data not in printed_domains:
                    prefix = f"[{label}] " if multi else ""
                    sys.stdout.write(f"\n--> {prefix}{data}\n")
                    sys.stdout.flush()
                    printed_domains.add(data)

            elif kind == 'error':
                sys.stdout.write(f"\n[error] [{label}] {data}\n")
                sys.stdout.flush()

            elif kind == 'done':
                done_count += 1
                if args.verbose:
                    sys.stdout.write(f"\n[done] [{label}] scanned {data} entries\n")
                    sys.stdout.flush()

        sys.stdout.write("\n--EOF\n")

    except KeyboardInterrupt:
        sys.stdout.write("\n--Interrupted\n")

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.stderr.flush()
        raise

    finally:
        elapsed = time.time() - start_time
        rate = int(total_scanned / elapsed) if elapsed > 0 else 0
        skip_summary = f"  ({skipped} log(s) skipped)" if skipped else ""
        found = len(printed_domains)
        found_summary = f"  |  {found} match{'es' if found != 1 else ''} found"
        sys.stdout.write(
            f"Scanned {total_scanned:,} entries across {workers_launched} log(s)"
            f"{skip_summary} in {elapsed:.1f}s  (~{rate:,} entries/s){found_summary}\n"
        )
        sys.stdout.flush()


if __name__ == '__main__':
    main()
