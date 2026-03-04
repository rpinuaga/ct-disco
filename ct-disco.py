#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ct-disco v0.3 - Direct CTL log querying
# Query Certificate Transparency logs directly

import sys
import time
import os
import argparse
import re
import json
import requests
import base64
import random

cert_count = 0
MAX = 1000  # Maximum number of certificate entries to process
BATCH_SIZE = 64  # Number of entries per API request
RATE_LIMIT_DELAY = 0.5  # Seconds to wait between API requests

# Adjust BATCH_SIZE to MAX to minimize HTTP requests
BATCH_SIZE = max(BATCH_SIZE, MAX)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Direct CTL log monitor')
parser.add_argument('-k', '--keyword', metavar='KEYWORD', default='skyscanner',
                    help='Keyword to search for in domains (letters, digits, underscore, dot, hyphen).')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose diagnostics.')
parser.add_argument('--start', metavar='START', type=int, default=None,
                    help='Starting entry index (randomized if not specified).')
args = parser.parse_args()

KEYWORD = args.keyword

# Syntax verification for the keyword
if not re.match(r'^[\w\.-]+$', KEYWORD):
    sys.stderr.write("Invalid keyword: '{}'. Allowed characters: letters, digits, underscore(_), dot(.) and hyphen(-).\n".format(KEYWORD))
    sys.exit(2)

def extract_root_domain(domain):
    """Extract root domain by stopping at known TLDs and cleaning garbage"""
    common_tlds = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'uk', 'us', 'de', 'fr',
        'au', 'jp', 'cn', 'in', 'br', 'ru', 'mx', 'ca', 'ch', 'nl', 'se', 'no', 'be',
        'at', 'it', 'es', 'pt', 'gr', 'ie', 'nz', 'sg', 'hk', 'tw', 'kr', 'th', 'id',
        'my', 'ph', 'vn', 'za', 'il', 'ae', 'sa', 'info', 'biz', 'name', 'mobi', 'asia',
        'tel', 'tv', 'cc', 'co', 'app', 'dev', 'ai', 'cloud', 'online', 'site', 'tech',
        'shop', 'store', 'blog', 'news', 'club', 'space', 'link', 'xyz', 'top', 'win',
        'bid', 'webcam', 'party', 'download', 'date', 'stream', 'gdn', 'review'
    }
    
    domain = domain.lower()
    
    # Use regex to find domain.tld pattern and stop there
    # Look for valid domain name + TLD, and strip any garbage after (digits, single letters, or more dots)
    tlds_pattern = '|'.join(common_tlds)
    match = re.search(r'(?:^|\.)([\w\-]+)\.(' + tlds_pattern + r')(?=[a-z]$|[a-z]\.|\d|\.|\Z)', domain)
    
    if match:
        name_part = match.group(1)
        tld_part = match.group(2)
        
        # Remove any trailing numbers from the name part
        while name_part and name_part[-1].isdigit():
            name_part = name_part[:-1]
        
        if name_part:
            return name_part + '.' + tld_part
    
    return domain

def extract_domains_from_binary(data):
    """Extract domain names from certificate binary data using regex"""
    domains = set()
    
    common_tlds = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'uk', 'us', 'de', 'fr',
        'au', 'jp', 'cn', 'in', 'br', 'ru', 'mx', 'ca', 'ch', 'nl', 'se', 'no', 'be',
        'at', 'it', 'es', 'pt', 'gr', 'ie', 'nz', 'sg', 'hk', 'tw', 'kr', 'th', 'id',
        'my', 'ph', 'vn', 'za', 'il', 'ae', 'sa', 'info', 'biz', 'name', 'mobi', 'asia',
        'tel', 'tv', 'cc', 'co', 'app', 'dev', 'ai', 'cloud', 'online', 'site', 'tech',
        'shop', 'store', 'blog', 'news', 'club', 'space', 'link', 'xyz', 'top', 'win',
        'bid', 'webcam', 'party', 'download', 'date', 'stream', 'gdn', 'review'
    }
    
    try:
        # Decode to string, ignoring errors, to find ASCII domain names
        text = data.decode('utf-8', errors='ignore')
        
        # Build pattern that only matches domains ending with known TLDs
        # Sort TLDs by length descending to match longer TLDs first (e.g., 'com' before 'co')
        sorted_tlds = sorted(common_tlds, key=len, reverse=True)
        tlds_pattern = '|'.join(sorted_tlds)
        # Use negative lookahead to ensure domain ends properly (not followed by alphanumeric or hyphen)
        pattern = r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:' + tlds_pattern + r')(?![a-z0-9-])'
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        for match in matches:
            if match.count('.') >= 1:  # At least one dot to be a valid domain
                # Filter out invalid patterns like single letters or garbage
                if len(match) > 3:
                    domains.add(match.lower())
    except:
        pass
    
    return list(domains)

def query_ctl_log(start_index):
    """Query CTL log for certificate entries"""
    try:
        url = f"https://ct.googleapis.com/logs/eu1/xenon2025h2/ct/v1/get-entries?start={start_index}&end={start_index + BATCH_SIZE - 1}"
        if args.verbose:
            sys.stdout.write(f"[query] {url}\n")
            sys.stdout.flush()
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            sys.stdout.write("[error] 404 Not Found - CTL endpoint unavailable\n")
            sys.stdout.flush()
        elif e.response.status_code == 503:
            sys.stdout.write("[error] 503 Service Unavailable - CTL server is temporarily down\n")
            sys.stdout.flush()
        else:
            if args.verbose:
                sys.stdout.write(f"[error] HTTP Error {e.response.status_code}: {e}\n")
                sys.stdout.flush()
        return None
    except requests.exceptions.Timeout as e:
        sys.stdout.write("[error] Read timeout - CTL server not responding\n")
        sys.stdout.flush()
        return None
    except Exception as e:
        if args.verbose:
            sys.stdout.write(f"[error] Query failed: {e}\n")
            sys.stdout.flush()
        return None

# MAIN
start_time = time.time()
sys.stdout.write("++ Querying CTL logs directly\n")
sys.stdout.write("++ Searching for keyword: " + KEYWORD + "\n")
sys.stdout.flush()

try:
    import requests
except Exception:
    sys.stderr.write("Missing dependency: requests. Install with `pip install requests`\n")
    sys.exit(1)

if args.verbose:
    sys.stdout.write("++ CTL Server: Google eu1/xenon2025h2\n")
    sys.stdout.flush()

# Randomize or use specified start index
if args.start is not None:
    index = args.start
else:
    index = random.randint(0, 100000000)  # Random starting point in the CTL log (100+ million entries)
    sys.stdout.write(f"++ Starting at random entry: {index}\n")
    sys.stdout.flush()

printed_domains = set()  # Track domains already printed to avoid duplicates

try:
    while cert_count < MAX:
        result = query_ctl_log(index)
        if result is None:
            break
        
        entries = result.get('entries', [])
        if not entries:
            if args.verbose:
                sys.stdout.write("[info] No more entries available\n")
                sys.stdout.flush()
            break
        
        for entry_idx, entry in enumerate(entries):
            if cert_count >= MAX:
                break
            
            try:
                leaf_input = entry.get('leaf_input', '')
                if leaf_input:
                    # Decode base64
                    cert_data = base64.b64decode(leaf_input)
                    
                    # Extract domains from binary data
                    domains = extract_domains_from_binary(cert_data)
                    
                    if domains:
                        for domain in domains:
                            if cert_count >= MAX:
                                break
                            
                            if args.verbose:
                                sys.stdout.write(f"\n[domain] {domain}\n")
                                sys.stdout.flush()
                            else:
                                sys.stdout.write(".")
                                sys.stdout.flush()
                            
                            # Search by keyword (case-insensitive)
                            if KEYWORD.lower() in domain.lower():
                                if domain not in printed_domains:
                                    sys.stdout.write("\n--> " + domain + "\n")
                                    printed_domains.add(domain)
                            
                            cert_count += 1
                    else:
                        sys.stdout.write(".")
                        sys.stdout.flush()
                        cert_count += 1
                else:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                    cert_count += 1
            except Exception as e:
                if args.verbose:
                    sys.stdout.write(f"\n[error] Failed to process entry: {e}\n")
                    sys.stdout.flush()
        
        index += BATCH_SIZE
        time.sleep(RATE_LIMIT_DELAY)  # Rate limit
        
        if args.verbose:
            sys.stdout.write(f"\n[progress] cert_count={cert_count}\n")
            sys.stdout.flush()

    sys.stdout.write("\n--EOF\n")
    end_time = time.time()
    elapsed_time = end_time - start_time
    sys.stdout.write("Time to process " + str(cert_count) + " entries: " + str(elapsed_time) + " seconds\n")
    sys.stdout.flush()

except KeyboardInterrupt:
    sys.stdout.write("\n--Interrupted\n")
    sys.stdout.flush()
except Exception as e:
    sys.stderr.write("Error: {}\n".format(e))
    sys.stderr.flush()
    raise
