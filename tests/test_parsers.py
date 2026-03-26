"""
Unit tests for parsers/parser.py

All tests are self-contained: mock files are written to a temp directory so
no external tools need to be installed.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.parser import (
    SubdomainParser,
    HttpParser,
    PortParser,
    DirectoryParser,
    VulnerabilityParser,
    UrlParser,
)
from tests.mock_data import MOCK_FILES


class ParserTestBase(unittest.TestCase):
    """Write mock files to a temp dir before each test."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        for filename, content in MOCK_FILES.items():
            path = os.path.join(self.tmpdir, filename)
            with open(path, "w") as f:
                f.write(content)

    def _path(self, filename):
        return os.path.join(self.tmpdir, filename)


class TestSubdomainParser(ParserTestBase):
    def setUp(self):
        super().setUp()
        self.parser = SubdomainParser()

    def test_parse_subfinder_returns_list(self):
        results = self.parser.parse_subfinder(self._path("subfinder.txt"))
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_parse_subfinder_host_field(self):
        results = self.parser.parse_subfinder(self._path("subfinder.txt"))
        hosts = [r["host"] for r in results]
        self.assertIn("www.example.com", hosts)
        self.assertIn("api.example.com", hosts)

    def test_parse_subfinder_source_tool(self):
        results = self.parser.parse_subfinder(self._path("subfinder.txt"))
        for r in results:
            self.assertEqual(r.get("source_tool"), "subfinder")


class TestHttpParser(ParserTestBase):
    def setUp(self):
        super().setUp()
        self.parser = HttpParser()

    def test_parse_httpx_returns_alive_hosts(self):
        results = self.parser.parse_httpx(self._path("httpx.jsonl"))
        self.assertGreater(len(results), 0)

    def test_parse_httpx_is_alive_flag(self):
        results = self.parser.parse_httpx(self._path("httpx.jsonl"))
        for r in results:
            self.assertTrue(r.get("is_alive"))

    def test_parse_httpx_has_ip(self):
        results = self.parser.parse_httpx(self._path("httpx.jsonl"))
        for r in results:
            self.assertIn("ip", r)


class TestPortParser(ParserTestBase):
    def setUp(self):
        super().setUp()
        self.parser = PortParser()

    def test_parse_nmap_returns_ports(self):
        results = self.parser.parse_nmap_xml(self._path("nmap_all.xml"))
        self.assertGreater(len(results), 0)

    def test_parse_nmap_port_fields(self):
        results = self.parser.parse_nmap_xml(self._path("nmap_all.xml"))
        for r in results:
            self.assertIn("port", r)
            self.assertIn("protocol", r)
            self.assertIn("service", r)

    def test_parse_nmap_port_80_present(self):
        results = self.parser.parse_nmap_xml(self._path("nmap_all.xml"))
        ports = [r["port"] for r in results]
        self.assertIn(80, ports)


class TestDirectoryParser(ParserTestBase):
    def setUp(self):
        super().setUp()
        self.parser = DirectoryParser()

    def test_parse_ffuf_returns_urls(self):
        results = self.parser.parse_ffuf(self._path("ffuf_all.json"))
        self.assertGreater(len(results), 0)

    def test_parse_ffuf_url_field(self):
        results = self.parser.parse_ffuf(self._path("ffuf_all.json"))
        for r in results:
            self.assertIn("url", r)
            self.assertTrue(r["url"].startswith("https://"))

    def test_parse_ffuf_source_tool(self):
        results = self.parser.parse_ffuf(self._path("ffuf_all.json"))
        for r in results:
            self.assertEqual(r.get("source_tool"), "ffuf")

    def test_parse_url_list_gau(self):
        url_parser = UrlParser()
        results = url_parser.parse_url_list(self._path("gau.txt"), "gau")
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertEqual(r["source_tool"], "gau")

    def test_parse_url_list_katana(self):
        url_parser = UrlParser()
        results = url_parser.parse_url_list(self._path("katana.txt"), "katana")
        self.assertGreater(len(results), 0)


class TestVulnerabilityParser(ParserTestBase):
    def setUp(self):
        super().setUp()
        self.parser = VulnerabilityParser()

    def test_parse_nuclei_returns_vulns(self):
        results = self.parser.parse_nuclei(self._path("nuclei_all.json"))
        self.assertGreater(len(results), 0)

    def test_parse_nuclei_severity_field(self):
        results = self.parser.parse_nuclei(self._path("nuclei_all.json"))
        severities = {r["severity"] for r in results}
        self.assertTrue(severities.issubset({"critical", "high", "medium", "low", "info"}))

    def test_parse_nuclei_critical_present(self):
        results = self.parser.parse_nuclei(self._path("nuclei_all.json"))
        crits = [r for r in results if r["severity"] == "critical"]
        self.assertGreater(len(crits), 0)

    def test_parse_nuclei_source_tool(self):
        results = self.parser.parse_nuclei(self._path("nuclei_all.json"))
        for r in results:
            self.assertEqual(r.get("tool"), "nuclei")


if __name__ == "__main__":
    unittest.main()
