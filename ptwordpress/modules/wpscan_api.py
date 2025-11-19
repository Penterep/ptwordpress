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
        self.http_client = HttpClient(self.args, self.ptjsonlib)

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


        if plugins:
            ptprint(f"Plugins known vulnerabilities:", "INFO", not self.args.json and plugins, colortext=True, newline_above=True)
            for plugin in plugins:
                self.get_plugin_vulnerabilities(plugin)
                if plugin != plugins[-1]:
                    ptprint(" ", "TEXT", condition=not self.args.json)

        if themes:
            ptprint(f"Themes known vulnerabilities:", "INFO", not self.args.json and themes, colortext=True, newline_above=True)
            for theme in themes:
                self.get_theme_vulnerabilities(theme)
                if theme != themes[-1]:
                    ptprint(" ", "TEXT", condition=not self.args.json)

    def get_vulnerabilities_by_wp_version(self, version: str):
        """Retrieve and print vulnerabilities from API"""
        if not version:
            ptprint(f"The exact version of WordPress is not known", "WARNING", condition=not self.args.json, indent=4)
            return
        
        response_data = self.send_request(url=self.API_URL + f"/wordpresses/{''.join(version.split('.'))}").json()
        if "is_error" in response_data.keys() or any(error_message in response_data.get("status", "") for error_message in ["error", "rate limit hit", "forbidden"]):
            ptprint(response_data, "TEXT", not self.args.json, indent=4)
            return

        ptprint(f"Vulnerabilities of WordPress version {version}:", "INFO", not self.args.json, colortext=True)
        response_data = response_data[version]

        if self.args.verbose:
            ptprint(f"Release date: {response_data.get('release_date')}", "ADDITIONS", colortext=True, condition=not self.args.json, indent=4)
            ptprint(f"Changelog: {response_data.get('changelog_url')}", "ADDITIONS", colortext=True, condition=not self.args.json, indent=4)
            status = response_data.get("status", "")
            ptprint(f"Status: {status}", "ADDITIONS", colortext=True, condition=not self.args.json and status, indent=4)
        
        self.show_vulerabilities(response_data=response_data)

    def get_plugin_vulnerabilities(self, plugin: str):
        response_data = self.send_request(url=self.API_URL + f"/plugins/{plugin}").json()
        if response_data.get(plugin) and "is_error" not in response_data.keys():
            response_data = response_data[plugin]
            self.show_vulerabilities(response_data=response_data)

    def get_theme_vulnerabilities(self, theme: str):
        response_data = self.send_request(url=self.API_URL + f"/themes/{theme}").json()
        if response_data.get(theme) and "is_error" not in response_data.keys():
            response_data = response_data[theme]
            self.show_vulerabilities(response_data=response_data)

    def show_vulerabilities(self, response_data: dict):
        vulnerabilities = response_data.get("vulnerabilities", [])
        if vulnerabilities:
            vulnerabilities_sorted = sorted(
                vulnerabilities,
                key=lambda v: v.get("title", "").lower()
            )
            for index, vulnerability in enumerate(vulnerabilities_sorted):
                cves = vulnerability.get("references", {}).get('cve') or []
                cves_output_list = ", ".join(f"CVE-{c}" for c in cves)
                cves_output_list = f" - {cves_output_list}" if cves_output_list else ""
                ptprint(f"{vulnerability.get('title')} ({vulnerability.get('vuln_type')}){cves_output_list}", "VULN", condition=not self.args.json, indent=4)

                if self.args.verbose:
                    ptprint(f"Fixed in: {vulnerability.get('fixed_in')}", "ADDITIONS", colortext=True, condition=not self.args.json, indent=4+4)
                    ptprint(f"References:", "ADDITIONS", colortext=True, condition=not self.args.json, indent=4+4)
                    
                    reference_urls = vulnerability.get("references", {}).get('url') or []
                    for url in reference_urls:
                        ptprint(url, "ADDITIONS", colortext=True, condition=not self.args.json, indent=4+4+4)

                    if index+1 != len(vulnerabilities_sorted):
                        ptprint(" ", "ADDITIONS", colortext=True, condition=not self.args.json)
        else:
            ptprint("No known vulnerabilities found", "OK", condition=not self.args.json, indent=4+4)

    def get_user_status_plan(self):
        url = self.API_URL + "/status"
        response = self.send_request(url=url)

        ptprint(f"User plan: {response.json().get('plan')}", "TEXT", condition=not self.args.json, indent=4)
        ptprint(f"Remaining requests: {response.json().get('requests_remaining')}", "TEXT", condition=not self.args.json, indent=4)
        ptprint(f"Requests limit: {response.json().get('requests_limit')}", "TEXT", condition=not self.args.json, indent=4)

        reset_time = datetime.utcfromtimestamp(response.json().get('requests_reset')).strftime('%H:%M:%S')
        if reset_time != "00:00:00":
            ptprint(f"Requests reset: {reset_time}", "TEXT", condition=not self.args.json, indent=4)

        ptprint(f" ", "TEXT", condition=not self.args.json, indent=4)

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
