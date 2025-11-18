import requests
from urllib.parse import urljoin
from ptlibs.http.http_client import HttpClient
from urllib.parse import urljoin

class SecurityToolsIdentifier:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(self.args, self.ptjsonlib)
        self.plugins = {

            "Wordfence Security": {
                "paths": [
                    "/wp-content/plugins/wordfence/",
                    "/wp-content/plugins/wordfence/js/",
                ],
                "rest": [
                    "/wp-json/wf/v1/",
                ],
                "headers": ["x-wf"],
            },

            "iThemes Security": {
                "paths": [
                    "/wp-content/uploads/ithemes-security/",
                ],
                "rest": [
                    "/wp-json/ithemes-security/v1/",
                ],
                "headers": ["x-itsec"],
            },

            "Sucuri Security": {
                "paths": [],
                "rest": [],
                "headers": ["x-sucuri-id"],
            },

            "WP Cerber Security": {
                "paths": [
                    "/wp-content/plugins/wp-cerber/",
                ],
                "rest": [
                    "/wp-json/cerber/v1/",
                ],
                "headers": [],
            },

            "NinjaFirewall": {
                "paths": [
                    "/wp-content/plugins/ninjafirewall/",
                ],
                "rest": [],
                "headers": ["x-ninjafirewall"],
            },

            "Shield Security": {
                "paths": [],
                "rest": [
                    "/wp-json/shield/v1/",
                ],
                "headers": ["x-sec"],
            },

            "MalCare Security": {
                "paths": [],
                "rest": [
                    "/wp-json/malcare/v1/",
                ],
                "headers": ["x-mc"],
            },

            "All in One WP Security": {
                "paths": [
                    "/wp-content/plugins/all-in-one-wp-security-and-firewall/",
                ],
                "rest": [],
                "headers": [],
            },

            "Defender Security": {
                "paths": [
                    "/wp-content/plugins/defender-security/",
                ],
                "rest": [
                    "/wp-json/defender/v2/",
                ],
                "headers": [],
            },

            "SecuPress": {
                "paths": [
                    "/wp-content/plugins/secupress/",
                ],
                "rest": [],
                "headers": [],
            }
        }


    def detect_plugins(self):
        found = {}

        # Get base headers (for WAF fingerprints)
        base_status, base_headers, _ = self.check_url(self.args.url)

        for name, data in self.plugins.items():
            indicators = []

            # Check paths
            for path in data["paths"]:
                status, _, _ = self.check_url(urljoin(self.args.url, path))
                if status and status < 400:
                    indicators.append(f"Accessible path: {path}")

            # Check REST endpoints
            for rest in data["rest"]:
                status, _, body = self.check_url(urljoin(self.args.url, rest))
                if status == 200 and body.strip():
                    indicators.append(f"REST endpoint: {rest}")

            # Check headers (either from base response or plugin endpoints)
            for h in data["headers"]:
                for resp_h in base_headers:
                    if resp_h.lower().startswith(h):
                        indicators.append(f"Header present: {resp_h}")

            if indicators:
                found[name] = indicators

        return found

    def check_url(self, url):
        try:
            r = self.http_client.send_request(url, method="GET")
            return r.status_code, r.headers, r.text[:300]
        except Exception:
            return None, {}, ""


        
