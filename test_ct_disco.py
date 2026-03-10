#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for ct-disco hostname parsing."""

import base64
import importlib.util
import json
import pathlib
import unittest
import urllib.error
import urllib.request

# ct-disco.py uses a hyphen, which is not a valid Python identifier, so we
# load it by file path rather than relying on normal import machinery.
_module_path = pathlib.Path(__file__).parent / "ct-disco.py"
_spec = importlib.util.spec_from_file_location("ct_disco", _module_path)
_ct_disco = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ct_disco)

extract_domains_from_binary = _ct_disco.extract_domains_from_binary

from tlds import VALID_TLDS  # noqa: E402 — normal import, tlds.py has a valid name

CTL_BASE = "https://ct.googleapis.com/logs/eu1/xenon2025h2/ct/v1/get-entries"


def _fetch_leaf(index):
    """Fetch a single CTL entry and return its decoded binary leaf_input."""
    url = f"{CTL_BASE}?start={index}&end={index}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.loads(resp.read())
    return base64.b64decode(data["entries"][0]["leaf_input"])


# ---------------------------------------------------------------------------
# Unit tests — no network required
# ---------------------------------------------------------------------------

class TestExtractDomainsFromBinary(unittest.TestCase):

    def test_simple_domain(self):
        """Single domain embedded in binary noise."""
        data = b'\x00\x01\x02example.com\x00\x03'
        self.assertIn('example.com', extract_domains_from_binary(data))

    def test_subdomain(self):
        """Subdomain is fully captured."""
        data = b'\x00www.example.com\x00'
        self.assertIn('www.example.com', extract_domains_from_binary(data))

    def test_multiple_domains(self):
        """Multiple domains (SANs) are all extracted."""
        data = b'\x00app.example.com\x00api.example.net\x00'
        domains = extract_domains_from_binary(data)
        self.assertIn('app.example.com', domains)
        self.assertIn('api.example.net', domains)

    def test_new_gtld(self):
        """New gTLDs outside the old hand-curated set are now recognised."""
        # .click, .online, .ninja were absent from the old COMMON_TLDS
        for domain in (b'pinaptrue-az.click', b'store.ninja', b'api.lncapilar.online'):
            with self.subTest(domain=domain):
                self.assertTrue(
                    extract_domains_from_binary(b'\x00' + domain + b'\x00'),
                    msg=f"{domain} should be extracted with full IANA TLD list",
                )

    def test_unknown_tld_rejected(self):
        """A domain with a made-up TLD is not extracted."""
        data = b'\x00example.invalidtld\x00'
        self.assertNotIn('example.invalidtld', extract_domains_from_binary(data))

    def test_wildcard_not_extracted(self):
        """Wildcard prefix (*.) is not matched — regex requires [a-z0-9] start."""
        data = b'\x00*.example.com\x00'
        self.assertNotIn('*.example.com', extract_domains_from_binary(data))

    def test_ip_like_domain_rejected(self):
        """
        Domains where the label before the TLD is all-digits are IP-address
        garbage and must be filtered out (e.g. www.rotrovisor11.000.000.000.co).
        """
        data = b'\x00www.rotrovisor11.000.000.000.co\x00'
        self.assertNotIn('www.rotrovisor11.000.000.000.co',
                         extract_domains_from_binary(data))
        # A valid domain with numeric subdomains must still be kept
        data2 = b'\x00web1.example.com\x00'
        self.assertIn('web1.example.com', extract_domains_from_binary(data2))

    def test_no_valid_domains(self):
        """Pure binary garbage produces no domains."""
        self.assertEqual(extract_domains_from_binary(bytes(range(256))), [])

    def test_empty_bytes(self):
        """Empty input produces no domains."""
        self.assertEqual(extract_domains_from_binary(b''), [])

    def test_domain_followed_by_asn1_tag(self):
        """
        DER-encoded certs place \\x30 (ASCII '0', the ASN.1 SEQUENCE tag)
        immediately after domain strings.  The parser must still extract them.
        """
        data = b'\x18flowers-to-the-world.com\x30\x0c\x06\x03'
        self.assertIn('flowers-to-the-world.com', extract_domains_from_binary(data))

    def test_known_ctl_entry_index_100_hardcoded(self):
        """
        Regression test using a hardcoded real CTL entry (Xenon2025h2, index 100).

        Certificate issued to 'flowers-to-the-world.com'.  The domain is followed
        by \\x30 in the DER encoding; earlier regex variants silently dropped it.
        """
        leaf_input_b64 = (
            "AAAAAAGJ5QUw1wAB43aJADBzoMZJzGVt6UbAMXTSXFZv48OAW4RvUjaUN5gAAtswggLX"
            "oAMCAQICBwYCppxF+NowDQYJKoZIhvcNAQELBQAwfzELMAkGA1UEBhMCR0IxDzANBgNV"
            "BAgMBkxvbmRvbjEXMBUGA1UECgwOR29vZ2xlIFVLIEx0ZC4xITAfBgNVBAsMGENlcnRp"
            "ZmljYXRlIFRyYW5zcGFyZW5jeTEjMCEGA1UEAwwaTWVyZ2UgRGVsYXkgSW50ZXJtZWRp"
            "YXRlIDEwHhcNMjMwODExMTQzNDI5WhcNMjUwODIwMTc1NTI5WjBjMQswCQYDVQQGEwJH"
            "QjEPMA0GA1UEBwwGTG9uZG9uMSgwJgYDVQQKDB9Hb29nbGUgQ2VydGlmaWNhdGUgVHJh"
            "bnNwYXJlbmN5MRkwFwYDVQQFExAxNjkxNzY0NDY5OTIyMDEwMIIBIjANBgkqhkiG9w0B"
            "AQEFAAOCAQ8AMIIBCgKCAQEAn0cz8o05rx/qXGZz5U+K8pbsd4sFzBfm4BqpGZOX0Fg5"
            "T70TA/4uqzPa68bQg71fPlG72EfbG9ZkPW5Af7I3ve28xxH4KA4mPRdiuZvX8xnpsW8Z"
            "nd/JvzQy7zMjaqfp8Dt1jfAM4tdyr/6zNhT+g32G5tjS/Xfdf5HxOj2V2Acn/au3RwEc"
            "EPTOFo55QfrJPQV4lr845HARCvw+77K/GXHnZKkcbnu/b5lqdoNqRjCJiH3EAitUciKu"
            "DyQX7nnsGvhtncvdwxMQoAF3M+FW5tQ8ve3kSz+tvN+mauPSotR84ZdbRRtLND8rD1cn"
            "t7FlTswdmodfZFri+PGjDy3cUwIDAQABo4GLMIGIMBMGA1UdJQQMMAoGCCsGAQUFBwMB"
            "MCMGA1UdEQQcMBqCGGZsb3dlcnMtdG8tdGhlLXdvcmxkLmNvbTAMBgNVHRMBAf8EAjAA"
            "MB8GA1UdIwQYMBaAFOk8BOGAL8KEEy0mcJ7y/RrPqv7GMB0GA1UdDgQWBBT5rAVeqaQ5"
            "nVNoYpXFcYeB6Y6SJAAA"
        )
        cert_data = base64.b64decode(leaf_input_b64)
        domains = extract_domains_from_binary(cert_data)
        self.assertIn('flowers-to-the-world.com', domains,
                      msg=f"Expected 'flowers-to-the-world.com'. Got: {domains}")


# ---------------------------------------------------------------------------
# Integration tests — require live network access to the CTL API
# ---------------------------------------------------------------------------

def _network_available():
    try:
        urllib.request.urlopen(CTL_BASE + "?start=100&end=100", timeout=5)
        return True
    except Exception:
        return False


@unittest.skipUnless(_network_available(), "CTL API not reachable")
class TestCTLIntegration(unittest.TestCase):
    """
    Fetch real certificate entries directly from the CTL log and verify
    that expected domains are extracted.  Each test documents the entry
    index so results can be reproduced with:
      curl "<CTL_BASE>?start=<INDEX>&end=<INDEX>"
    """

    def test_entry_100_flowers_to_the_world(self):
        """
        Xenon2025h2 index 100 — certificate for flowers-to-the-world.com.
        Verifies that a .com domain followed by DER byte \\x30 is extracted.
        """
        cert_data = _fetch_leaf(100)
        domains = extract_domains_from_binary(cert_data)
        self.assertIn('flowers-to-the-world.com', domains,
                      msg=f"Got: {domains}")

    def test_entry_96476130_digicert_issuer(self):
        """
        Xenon2025h2 index 96476130 — DigiCert-issued certificate.
        Verifies extraction of .com domains from a real Sectigo/DigiCert bundle.
        """
        cert_data = _fetch_leaf(96476130)
        domains = extract_domains_from_binary(cert_data)
        # euro-reifen.de appears in the SAN of this certificate
        self.assertIn('euro-reifen.de', domains,
                      msg=f"Got: {domains}")

    def test_entry_96476139_click_tld(self):
        """
        Xenon2025h2 index 96476139 — certificate for pinaptrue-az.click.
        Verifies that the .click gTLD (absent from the old hand-curated list)
        is now recognised via the full IANA VALID_TLDS set.
        """
        cert_data = _fetch_leaf(96476139)
        domains = extract_domains_from_binary(cert_data)
        self.assertTrue(
            any('click' in d for d in domains),
            msg=f"Expected a .click domain. Got: {domains}",
        )

    def test_entry_96476138_amazonaws(self):
        """
        Xenon2025h2 index 96476138 — Amazon kafka canary certificate.
        Verifies multi-label subdomain extraction (kafka.eu-west-1.amazonaws.com).
        """
        cert_data = _fetch_leaf(96476138)
        domains = extract_domains_from_binary(cert_data)
        self.assertTrue(
            any('amazonaws.com' in d for d in domains),
            msg=f"Expected an amazonaws.com domain. Got: {domains}",
        )


if __name__ == '__main__':
    unittest.main()
