import requests
from urllib.parse import urljoin
from ptlibs.http.http_client import HttpClient
from urllib.parse import urljoin
from modules.wp_paths import wp_directory_path

class SecurityToolsIdentifier:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(self.args, self.ptjsonlib)
        self.plugins = {

            "Wordfence Security": {
                "paths": [
                    wp_directory_path(self.args, "content", "plugins/wordfence", trailing_slash=True),
                    wp_directory_path(self.args, "content", "plugins/wordfence/js", trailing_slash=True),
                ],
                "rest": [
                    wp_directory_path(self.args, "json", "wf/v1", trailing_slash=True),
                ],
                "headers": ["x-wf"],
            },

            "iThemes Security": {
                "paths": [
                    wp_directory_path(self.args, "content", "uploads/ithemes-security", trailing_slash=True),
                ],
                "rest": [
                    wp_directory_path(self.args, "json", "ithemes-security/v1", trailing_slash=True),
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
                    wp_directory_path(self.args, "content", "plugins/wp-cerber", trailing_slash=True),
                ],
                "rest": [
                    wp_directory_path(self.args, "json", "cerber/v1", trailing_slash=True),
                ],
                "headers": [],
            },

            "NinjaFirewall": {
                "paths": [
                    wp_directory_path(self.args, "content", "plugins/ninjafirewall", trailing_slash=True),
                ],
                "rest": [],
                "headers": ["x-ninjafirewall"],
            },

            "Shield Security": {
                "paths": [],
                "rest": [
                    wp_directory_path(self.args, "json", "shield/v1", trailing_slash=True),
                ],
                "headers": ["x-sec"],
            },

            "MalCare Security": {
                "paths": [],
                "rest": [
                    wp_directory_path(self.args, "json", "malcare/v1", trailing_slash=True),
                ],
                "headers": ["x-mc"],
            },

            "All in One WP Security": {
                "paths": [
                    wp_directory_path(self.args, "content", "plugins/all-in-one-wp-security-and-firewall", trailing_slash=True),
                ],
                "rest": [],
                "headers": [],
            },

            "Defender Security": {
                "paths": [
                    wp_directory_path(self.args, "content", "plugins/defender-security", trailing_slash=True),
                ],
                "rest": [
                    wp_directory_path(self.args, "json", "defender/v2", trailing_slash=True),
                ],
                "headers": [],
            },

            "SecuPress": {
                "paths": [
                    wp_directory_path(self.args, "content", "plugins/secupress", trailing_slash=True),
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


        
