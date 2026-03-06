import unittest
from unittest.mock import patch, MagicMock
import json

import main


class TestDNSRecon(unittest.TestCase):
    @patch("main.console.print")  # suppress rich tables
    @patch("main.dns.resolver.resolve")
    def test_dnsrecon_collects_expected_records(self, mock_resolve, _mock_console):
        def fake_resolve(domain, rtype):
            if rtype == "A":
                return ["1.2.3.4"]
            if rtype == "MX":
                return ["mail.example.com"]
            raise Exception("no record")

        mock_resolve.side_effect = fake_resolve

        target = main.Target("example.com")
        dns_module = main.DNSRecon("DNS Enumeration", target)
        dns_module.run()

        output = dns_module.get_output()
        print("\n[DNSRecon] Output:\n", json.dumps(output, indent=2))
        self.assertEqual(output["A"], ["1.2.3.4"])
        self.assertEqual(output["MX"], ["mail.example.com"])
        self.assertNotIn("TXT", output)
        print("[DNSRecon] Test OK\n")


class TestWhoisRecon(unittest.TestCase):
    @patch("main.console.print")  # suppress WHOIS panel
    @patch("main.whois.whois")
    def test_whoisrecon_processes_basic_fields(self, mock_whois, _mock_console):
        class DummyWhois:
            domain_name = "example.com"
            registrar = "Test Registrar"
            creation_date = "2020-01-01"
            expiration_date = "2030-01-01"
            emails = ["admin@example.com"]
            name_servers = ["ns1.example.com", "ns2.example.com"]

        mock_whois.return_value = DummyWhois()

        target = main.Target("example.com")
        whois_module = main.WhoisRecon("WHOIS Lookup", target)
        whois_module.run()

        output = whois_module.get_output()
        print("\n[WhoisRecon ] Output:\n", json.dumps(output, indent=2, default=str))
        self.assertEqual(output["Domain Name"], "example.com")
        self.assertEqual(output["Registrar"], "Test Registrar")
        self.assertIn("admin@example.com", output["Emails"])
        self.assertIn("ns1.example.com", output["Name Servers"])
        print("[WhoisRecon OK] Test OK\n")


class TestSubdomainFinder(unittest.TestCase):
    def test_bruteforce_subdomains_uses_wordlist(self):
        target = main.Target("example.com")
        sub_module = main.SubdomainFinder("Subdomain Finder", target)
        brute = sub_module._bruteforce_subdomains()
        expected_prefixes = {"mail", "dev", "test", "api", "www", "vpn", "login", "academy", "support", "upload", "blog", "smtp"}
        print("\n[SubdomainFinder Bruteforce] Output:\n", json.dumps(brute, indent=2))
        self.assertTrue(all(s.endswith(".example.com") for s in brute))
        self.assertEqual({s.split(".")[0] for s in brute}, expected_prefixes)
        print("[SubdomainFinder Bruteforce] Test OK\n")

    @patch("main.requests.get")
    def test_enumerate_crtsh_parses_only_matching_domain(self, mock_get):
        class DummyResponse:
            status_code = 200

            def json(self):
                return [
                    {"name_value": "a.example.com\nb.example.org\nexample.com"},
                    {"name_value": "c.example.com"},
                ]

        mock_get.return_value = DummyResponse()

        target = main.Target("example.com")
        sub_module = main.SubdomainFinder("Subdomain Finder", target)
        result = sub_module._enumerate_crtsh()

        print("\n[SubdomainFinder crt.sh] Output:\n", json.dumps(result, indent=2))
        self.assertIn("a.example.com", result)
        self.assertIn("c.example.com", result)
        self.assertIn("example.com", result)
        self.assertNotIn("b.example.org", result)

    @patch("main.console.print")  # suppress rich tables
    def test_subdomainfinder_run_combines_sources_and_filters_by_resolve(self, _mock_console):
        target = main.Target("example.com")
        sub_module = main.SubdomainFinder("Subdomain Finder", target)

        sub_module._enumerate_crtsh = lambda: ["a.example.com", "b.example.com"]
        sub_module._bruteforce_subdomains = lambda: ["c.example.com"]
        sub_module._resolve = lambda sub: not sub.startswith("b.")

        sub_module.run()
        output = sub_module.get_output()

        print("\n[SubdomainFinder run] Output:\n", json.dumps(output, indent=2))
        self.assertEqual(set(output["subdomains"]), {"a.example.com", "c.example.com"})
        print("[SubdomainFinder run] Test OK\n")


class TestSocialFootprint(unittest.TestCase):
    @patch("main.requests.get")
    def test_platform_checks_records_existing_profiles(self, mock_get):
        def fake_get(url, headers=None, timeout=None):
            if "github.com/example" in url or "x.com/example" in url:
                resp = MagicMock()
                resp.status_code = 200
                return resp
            resp = MagicMock()
            resp.status_code = 404
            return resp

        mock_get.side_effect = fake_get

        target = main.Target("example.com")
        soc_module = main.SocialFootprint("Social Footprint", target)
        soc_module._platform_checks()

        platforms = {(p["platform"], p["username"]) for p in soc_module.found_profiles}
        print(
            "\n[SocialFootprint platforms] Output:\n",
            json.dumps(soc_module.found_profiles, indent=2),
        )
        self.assertIn(("GitHub", "example"), platforms)
        self.assertIn(("Twitter", "example"), platforms)
        print("[SocialFootprint platforms] Test OK\n")

    @patch("main.DDGS")
    def test_search_mentions_engine_collects_results(self, mock_ddgs):
        mock_ctx = MagicMock()
        mock_ctx.text.return_value = [
            {"title": "Example result", "href": "https://example.com"},
            {"title": "Another", "href": "https://another.com"},
        ]
        mock_ddgs.return_value.__enter__.return_value = mock_ctx

        target = main.Target("example.com")
        soc_module = main.SocialFootprint("Social Footprint", target)
        soc_module._search_mentions_engine()

        links = {m["link"] for m in soc_module.search_mentions}
        print(
            "\n[SocialFootprint mentions] Output:\n",
            json.dumps(soc_module.search_mentions, indent=2),
        )
        self.assertIn("https://example.com", links)
        self.assertIn("https://another.com", links)
        print("[SocialFootprint mentions] Test OK\n")

if __name__ == "__main__":
    unittest.main()

