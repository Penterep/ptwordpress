import requests
import json
from datetime import datetime
from ptlibs.ptprinthelper import ptprint
from ptlibs.http.http_client import HttpClient

class WPScanAPI:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.API_URL = "https://wpscan.com/wp-json/api/v3"
        self.API_KEY = args.wpscan_key
        self.headers = {}
        self.headers.update({"Authorization": f"Token token={args.wpscan_key}"})
        self.http_client = HttpClient()

    def run(self, wp_version: str, plugins: list, themes: list):
        ptprint(f"WPScan", "INFO", not self.args.json, colortext=True, newline_above=True)
        if not self.API_KEY or len(self.API_KEY) != 43:
            ptprint(f"Valid API key is required for WPScan information (--wpscan-key)", "WARNING", condition=not self.args.json, indent=4)
            return

        json_data = self.get_user_status_plan()

        if json_data.get('status', '').lower() == "unauthorized":
            ptprint(f"Not authorized", "WARNING", condition=not self.args.json, indent=4)
            return

        if json_data.get('requests_remaining') < 1:
            ptprint(f"No requests remaining", "WARNING", condition=not self.args.json, indent=4)
            return

        else:
            self.get_vulnerabilities_by_wp_version(version=wp_version)

            ptprint(f"Plugin result:", "INFO", not self.args.json and plugins, colortext=True, newline_above=True)
            for plugin in plugins:
                self.get_plugin_vulnerabilities(plugin)
                if plugin != plugins[-1]:
                    ptprint(" ", "TEXT", condition=not self.args.json)

            ptprint(f"Theme result:", "INFO", not self.args.json and themes, colortext=True, newline_above=True)
            for theme in themes:
                self.get_theme_vulnerabilities(theme)
                if theme != themes[-1]:
                    ptprint(" ", "TEXT", condition=not self.args.json)

    def get_vulnerabilities_by_wp_version(self, version: str):
        """Retrieve and print vulnerabilities from API"""
        if not version: return
        response_data = self.send_request(url=self.API_URL + f"/wordpresses/{''.join(version.split('.'))}").json()
        if "is_error" in response_data.keys() or any(error_message in response_data.get("status", "") for error_message in ["error", "rate limit hit", "forbidden"]):
            ptprint(response_data, "TEXT", not self.args.json, indent=4)
            return

        ptprint(f"Wordpress version {version}:", "INFO", not self.args.json, colortext=True)
        response_data = response_data[version]
        ptprint(f"Release date: {response_data.get('release_date')}", "TEXT", condition=not self.args.json, indent=4)
        ptprint(f"Changelog: {response_data.get('changelog_url')}", "TEXT", condition=not self.args.json, indent=4)
        status = response_data.get("status", "")
        ptprint(f"Status: {status}", "TEXT", condition=not self.args.json and status, indent=4)
        ptprint(f"Vulnerabilities: ", "TEXT", condition=not self.args.json, indent=4)
        if response_data.get("vulnerabilities", []):
            for index, vulnerability in enumerate(response_data.get("vulnerabilities", [])):
                ptprint(f"Title: {vulnerability.get('title')}", "TEXT", condition=not self.args.json, indent=4+4)
                ptprint(f"Type: {vulnerability.get('vuln_type')}", "TEXT", condition=not self.args.json, indent=4+4)
                ptprint(f"Fixed in: {vulnerability.get('fixed_in')}", "TEXT", condition=not self.args.json, indent=4+4)
                ptprint(f"References:", "TEXT", condition=not self.args.json, indent=4+4)
                for key, value in vulnerability.get("references", {}).items():
                    ptprint(f"{key.capitalize()}:", "TEXT", condition=not self.args.json, indent=4+4+4)
                    for v in value:
                        ptprint(v, "TEXT", condition=not self.args.json, indent=4+4+4+4)

                if index+1 != len(response_data.get("vulnerabilities", [])):
                    ptprint(" ", "TEXT", condition=not self.args.json)
        else:
            ptprint("None", "TEXT", condition=not self.args.json, indent=4+4)

    def get_plugin_vulnerabilities(self, plugin: str):
        response_data = self.send_request(url=self.API_URL + f"/plugins/{plugin}").json()
        if "is_error" in response_data.keys():
            ptprint(response_data.get("status", ""), "TEXT", not self.args.json, indent=4)
            return

        if response_data.get(plugin):
            response_data = response_data[plugin]

            ptprint(f"{plugin}", "TEXT", not self.args.json, indent=4)
            ptprint(f"Name: {response_data.get('friendly_name', 'UNKNOWN')}", "TEXT", not self.args.json, indent=4)
            ptprint(f"Latest version: {response_data.get('latest_version', 'UNKNOWN')}", "TEXT", not self.args.json, indent=4)

            if response_data.get("vulnerabilities", []):
                for index, vulnerability in enumerate(response_data.get("vulnerabilities", [])):

                    ptprint(f"Title: {vulnerability.get('title')}", "TEXT", condition=not self.args.json, indent=4+4)
                    ptprint(f"Type: {vulnerability.get('vuln_type')}", "TEXT", condition=not self.args.json, indent=4+4)
                    ptprint(f"Fixed in: {vulnerability.get('fixed_in')}", "TEXT", condition=not self.args.json, indent=4+4)
                    ptprint(f"References:", "TEXT", condition=not self.args.json, indent=4+4)

                    for key, value in vulnerability.get("references", {}).items():
                        ptprint(f"{key.capitalize()}:", "TEXT", condition=not self.args.json, indent=4+4+4)
                        for v in value:
                            ptprint(v, "TEXT", condition=not self.args.json, indent=4+4+4+4)

                    if index+1 != len(response_data.get("vulnerabilities", [])):
                        ptprint(" ", "TEXT", condition=not self.args.json)

    def get_theme_vulnerabilities(self, theme: str):
        response_data = self.send_request(url=self.API_URL + f"/themes/{theme}").json()
        if "is_error" in response_data.keys():
            ptprint(response_data.get("status", ""), "TEXT", not self.args.json, indent=4)
            return

        response_data = response_data[theme]
        ptprint(f"{theme}", "TEXT", not self.args.json, indent=4)
        ptprint(f"Name: {response_data.get('friendly_name', 'UNKNOWN')}", "TEXT", not self.args.json, indent=4)
        ptprint(f"Latest version: {response_data.get('latest_version', 'UNKNOWN')}", "TEXT", not self.args.json, indent=4)

        if response_data.get("vulnerabilities", []):
            for index, vulnerability in enumerate(response_data.get("vulnerabilities", [])):

                ptprint(f"Title: {vulnerability.get('title')}", "TEXT", condition=not self.args.json, indent=4+4)
                ptprint(f"Type: {vulnerability.get('vuln_type')}", "TEXT", condition=not self.args.json, indent=4+4)
                ptprint(f"Fixed in: {vulnerability.get('fixed_in')}", "TEXT", condition=not self.args.json, indent=4+4)
                ptprint(f"References:", "TEXT", condition=not self.args.json, indent=4+4)

                for key, value in vulnerability.get("references", {}).items():
                    ptprint(f"{key.capitalize()}:", "TEXT", condition=not self.args.json, indent=4+4+4)
                    for v in value:
                        ptprint(v, "TEXT", condition=not self.args.json, indent=4+4+4+4)

                if index+1 != len(response_data.get("vulnerabilities", [])):
                    ptprint(" ", "TEXT", condition=not self.args.json)

    def get_user_status_plan(self):
        url = self.API_URL + "/status"
        response = self.send_request(url=url)

        ptprint(f"User plan: {response.json().get('plan')}", "TEXT", condition=not self.args.json, indent=4)
        ptprint(f"Remaining requests: {response.json().get('requests_remaining')}", "TEXT", condition=not self.args.json, indent=4)
        ptprint(f"Requests limit: {response.json().get('requests_limit')}", "TEXT", condition=not self.args.json, indent=4)

        reset_time = datetime.utcfromtimestamp(response.json().get('requests_reset')).strftime('%H:%M:%S')
        if reset_time != "00:00:00":
            ptprint(f"Requests reset: {reset_time}", "TEXT", condition=not self.args.json, indent=4)

        return response.json()

    def send_request(self, url: str, data: dict = {}):
        try:
            response = self.http_client.send_request(url, method="GET", headers=self.headers)

            if response.json().get("status", "") == "rate limit hit":
                ptprint(f"Rate limit hit", "TEXT", condition=not self.args.json, indent=4)
                raise

            return response
        except Exception as e:
            raise e
