import urllib
import socket
import re
import os
import csv
import concurrent.futures

import requests

from modules.http_client import HttpClient
from modules.release_badges import known_svg_badge_hashes
from modules.plugins.hashes import Hashes

from ptlibs import ptmisclib, ptprinthelper
from ptlibs.ptprinthelper import ptprint

import defusedxml.ElementTree as ET
from bs4 import BeautifulSoup, Comment


class Helpers:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.BASE_URL, self.REST_URL     = self.construct_wp_api_url(args.url)
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def print_response_headers(self, response):
        """Print all response headers"""
        ptprint(f"Response headers:", "INFO", not self.args.json, colortext=True)
        for header_name, header_value in response.raw.headers.items():
            ptprint(f"{header_name}: {header_value}", "ADDITIONS", not self.args.json, colortext=True, indent=4)

    def check_if_target_is_wordpress(self, base_response: object, wp_json_response: object) -> bool:
        """Checks if target runs wordpress, if not script will be terminated."""
        if not any(substring in base_response.text.lower() for substring in ["wp-content/", "wp-includes/", "wp-json/"]):
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, indent=0)
            try:
                response = self.http_client.send_request(self.BASE_URL + "/wp-content/", headers=self.args.headers, allow_redirects=False)
                if response.status_code != 404:
                    self.ptjsonlib.end_error(f"WordPress discovered but target URL is not posible to test. Check for redirect and try another URL.", self.args.json)
            except requests.exceptions.RequestException:
                pass
            self.ptjsonlib.end_error(f"Target doesn't seem to be running wordpress.", self.args.json)

    def parse_google_identifiers(self, response):
        ptprinthelper.ptprint(f"Google identifiers", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        regulars = {
            "Google Tag Manager ID": r"(GTM-[A-Z0-9]{6,9})",
            "Google Analytics Universal ID": r"(UA-\d{4,10}-\d+)",
            "Google Analytics 4": r"(G-[A-Z0-9]{8,12})",
            "Google Ads Conversion ID": r"(AW-\d{9,12})",
            "Google Campaign Manager ID": r"(DC-\d{6,10})",
            "Google AdSense Publisher ID" : r"(ca-pub-\d{16})|(ca-ads-\d{16})",
            "Google API Keys": r"AIza[0-9A-z_\-\\]{35}",
        }

        found_identifiers = {}
        for key, regex in regulars.items():
            matches = re.findall(regex, response.text)
            matches = [m[0] if isinstance(m, tuple) else m for m in matches]
            matches = sorted(set(matches))
            if matches:
                found_identifiers[key] = matches

        if found_identifiers:
            for category, values in found_identifiers.items():
                ptprinthelper.ptprint(f"{category}:", "TEXT", condition=not self.args.json, indent=4)
                ptprinthelper.ptprint("\n        ".join(values), "TEXT", condition=not self.args.json, indent=8)
        else:
            ptprinthelper.ptprint("No identifiers found", "OK", condition=not self.args.json, indent=4)

    def get_target_ip(self, base_response):
        hostname = urllib.parse.urlparse(base_response.url).hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address

    def check_case_sensitivity(self, url):
        """Returns True if target is case sensitive by testing favicon"""
        response = self.http_client.send_request(self.BASE_URL + "/favicon.ico", headers=self.args.headers, allow_redirects=True)

        url_to_favicon_uppercase = '/'.join([response.url.rsplit("/", 1)[0], response.url.rsplit("/", 1)[1].upper()]) # Path to favicon coverted to upper case
        response2 = self.http_client.send_request(url_to_favicon_uppercase, headers=self.args.headers, allow_redirects=False)
        ptprint(f"Case sensitivity", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)

        if response2.status_code == 200:
            ptprint(f"Target system use no case sensitive OS (Windows)", "TEXT", condition=not self.args.json, indent=4)
            return False
        else:
            ptprint(f"Target system use case sensitive OS (Linux)", "TEXT", condition=not self.args.json, indent=4)
            return True

    def check_if_behind_cloudflare(self, base_response: object):
        """Check if target is behind cloudflare"""
        if any(header.lower() in ["cf-edge-cache", "cf-cache-status", "cf-ray"] for header in base_response.headers.keys()):
            ptprinthelper.ptprint("Target site is behind Cloudflare, results may not be accurate.", "WARNING", condition=not self.args.json, indent=0, newline_above=True)
            return True

    def _is_head_method_allowed(self, url) -> bool:
        """Tests if HEAD method is allowed on target url"""
        try:
            response = self.http_client.send_request(url=f"{self.BASE_URL}/favicon.ico", method="HEAD", allow_redirects=True, headers=self.args.headers)
            return True if response.status_code == 200 else False
        except:
            return False

    def construct_wp_api_url(self, url: str) -> None:
        """
        Constructs the URL for the WordPress REST API endpoint (`wp-json`)
        based on the given base URL.

        Args:
            url (str): The base URL of the WordPress site (e.g., 'https://example.com').

        Returns:
            str: The constructed URL for the WordPress REST API endpoint (e.g., 'https://example.com/wp-json').
        """
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme.lower() not in ["http", "https"]:
            self.ptjsonlib.end_error(f"Missing or wrong scheme", self.args.json)

        base_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
        rest_url = base_url + "/wp-json"
        return base_url, rest_url

    def parse_site_info_from_rest(self, rest_response, base_response, is_cloudflare):
        """Parse site info from rest response"""
        ptprinthelper.ptprint(f"Site info", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        try:
            rest_response.json()
            if rest_response is not None and rest_response.status_code != 200:
                raise Exception
        except Exception as e:
            print_api_is_not_available(status_code=getattr(rest_response, "status_code", None))
            return

        rest_response = rest_response.json()
        site_description = rest_response.get("description", "")
        site_name = rest_response.get("name", "")
        site_home = rest_response.get("home", "")
        site_gmt = rest_response.get("gmt_offset", "")
        site_timezone = rest_response.get("timezone_string", "")
        _timezone =  f"{str(site_timezone)} (GMT{'+' if not '-' in str(site_gmt) else '-'}{str(site_gmt)})" if site_timezone else ""

        ptprinthelper.ptprint(f"Name: {site_name}", "TEXT", condition=not self.args.json, indent=4)
        ptprinthelper.ptprint(f"Description: {site_description}", "TEXT", condition=not self.args.json, indent=4)
        ptprinthelper.ptprint(f"Home: {site_home}", "TEXT", condition=not self.args.json, indent=4)
        ptprinthelper.ptprint(f"Timezone: {_timezone}", "TEXT", condition=not self.args.json, indent=4)
        ptprinthelper.ptprint(f"IP Address: {self.get_target_ip(base_response)} {'(Cloudflare)' if is_cloudflare else ''}", "TEXT", condition=not self.args.json, indent=4)

    def parse_namespaces_from_rest(self, rest_response):
        if not self.try_parse_response_json(rest_response=rest_response):
            return
        ptprinthelper.ptprint(f"Namespaces (API provided by addons)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        rest_response = rest_response.json()
        namespaces = rest_response.get("namespaces", [])
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "plugin_list.csv"), mode='r') as file:
            csv_reader = csv.reader(file)
            csv_data = list(csv_reader)

        if "wp/v2" in namespaces: # wp/v2 is prerequirement
            #has_v2 = True
            for namespace in namespaces:
                namespace_description = self.find_description_in_csv(csv_data, namespace)
                ptprinthelper.ptprint(f"{namespace} {namespace_description}", "TEXT", condition=not self.args.json, indent=4)

    def find_description_in_csv(self, csv_data, text: str):
        # Iterate over the rows in the CSV file
        for row in csv_data:
            if row[0] == text:
                if row[2]:
                    return f"- {row[1]} ({row[2]})"
                else:
                    return f"- {row[1]}"
        return ""

    def try_parse_response_json(self, rest_response):
        try:
            if rest_response is not None and rest_response.status_code != 200:
                raise Exception
            return rest_response.json()
        except Exception as e:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))

    def extract_and_print_html_comments(self, response):
        soup = BeautifulSoup(response.content, 'lxml')
        # Find all comments in the HTML
        comments = {comment for comment in soup.find_all(string=lambda text: isinstance(text, Comment))}
        if comments:
            ptprint(f"HTML comments", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
            for comment in comments:
                comment = str(comment).strip().replace("\n", "\n    ")
                ptprint(comment, "TEXT", condition=not self.args.json, colortext=True, indent=4)
        return comments

    def extract_and_print_meta_tags(self, response) -> list:
        content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "")
        if "text/html" not in content_type:
            return
        soup = BeautifulSoup(response.text, "lxml")
        meta_tags = soup.find_all("meta")
        if meta_tags:
            ptprint(f"Meta tags", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
            for meta in meta_tags:
                ptprint(meta, "ADDITIONS", condition=not self.args.json, colortext=True, indent=4)
        return meta_tags

    def print_robots_txt(self, robots_txt_response):
        if robots_txt_response is not None and robots_txt_response.status_code == 200:
            ptprinthelper.ptprint(f"Robots.txt", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
            for line in robots_txt_response.text.splitlines():
                ptprinthelper.ptprint(line, "TEXT", condition=not self.args.json, indent=4)

    def print_supported_wordpress_versions(self, wp_version):
        def format_versions(versions: list):
            formatted_output = "    "
            major_version = None
            line_parts = []

            for version in versions:
                major = version.split('.')[0]
                if major_version is None:
                    major_version = major

                if major != major_version:
                    formatted_output += ', '.join(line_parts) + ',\n    '
                    line_parts = []
                    major_version = major

                line_parts.append(version)

            formatted_output += ', '.join(line_parts)  # Add last row
            return formatted_output

        ptprint(f"Supported version", "TITLE", not self.args.json, colortext=True, newline_above=True)
        response = self.http_client.send_request("https://api.wordpress.org/core/version-check/1.7/", allow_redirects=False, headers=self.args.headers)

        latest_available_version: str = response.json()["offers"][0]["version"]
        supported_versions: list = []
        index: int = 1
        while True:
            try:
                _version = response.json()["offers"][index]["version"]
                supported_versions.append(_version)
                index += 1
            except IndexError:
                break

        ptprint(f"Recommended version: {latest_available_version}", "TEXT", not self.args.json, indent=4)
        ptprint(f"Supported versions:\n{format_versions(supported_versions)}", "TEXT", not self.args.json, indent=4)
        if wp_version is None:
            ptprint(f"Unknown wordpress version", "WARNING", not self.args.json, indent=4)
        elif wp_version not in supported_versions:
            ptprint(f"Target uses unsupported version: {wp_version}.", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"{'Target uses latest version: ' if wp_version == latest_available_version else 'Target uses supported version: '}" + f"{wp_version}", "OK", not self.args.json, indent=4)

    def process_sitemap(self, robots_txt_response):
        """Test sitemap"""
        ptprint(f"Sitemap", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        try:
            sitemap_response = self.http_client.send_request(self.BASE_URL + "/sitemap.xml", allow_redirects=False, headers=self.args.headers)
            if sitemap_response.status_code == 200:
                ptprint(f"Sitemap exists: {sitemap_response.url}", "OK", condition=not self.args.json, indent=4)
            elif sitemap_response.is_redirect:
                ptprint(f"[{sitemap_response.status_code}] {self.BASE_URL + "/sitemap.xml"} -> {sitemap_response.headers.get("location")}", "OK", condition=not self.args.json, indent=4)
            else:
                ptprint(f"[{sitemap_response.status_code}] {sitemap_response.url}", "WARNING", condition=not self.args.json, indent=4)
        except requests.exceptions.RequestException:
            ptprint(f"Error retrieving sitemap from {self.BASE_URL + '/sitemap.xml'}", "WARNING", condition=not self.args.json, indent=4)

        # Process robots.txt sitemaps
        if robots_txt_response.status_code == 200:
            _sitemap_url: list = re.findall(r"Sitemap:(.*)\b", robots_txt_response.text, re.IGNORECASE)
            if _sitemap_url:
                ptprint(f"Sitemap{'s' if len(_sitemap_url) > 1 else ''} in robots.txt:", "OK", condition=not self.args.json, indent=4)
                for url in _sitemap_url:
                    ptprint(f"{url}", "TEXT", condition=not self.args.json, indent=4+3)

    def get_wordpress_version(self, base_response, rss_response, meta_tags, head_method_allowed):
        """Retrieve wordpress version from metatags, rss feed, API, ... """
        ptprint(f"Wordpress version", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        wp_version = None
        svg_badge_response = self.http_client.send_request(url=f"{self.BASE_URL}/wp-admin/images/about-release-badge.svg", method="GET", allow_redirects=False, headers=self.args.headers)
        if svg_badge_response.status_code == 200:
            ptprinthelper.ptprint(f"{svg_badge_response.url}", "VULN", condition=not self.args.json, indent=4)

            # Get sha 256 hash from response and compare with local db
            response_hash = Hashes(self.args).calculate_hashes(svg_badge_response.content)["SHA256"]
            for key, value in known_svg_badge_hashes.items():
                if value == response_hash:
                    ptprinthelper.ptprint(f"Detected version: {key} (hash detection)", "VULN", condition=not self.args.json, indent=4)
                    break

        opml_response = self.http_client.send_request(url=f"{self.BASE_URL}/wp-links-opml.php", method="GET", allow_redirects=False, headers=self.args.headers)
        if opml_response.status_code == 200:
            wp_version = re.findall(r"WordPress.*(\d\.\d\.[\d.]+)", opml_response.text)
            if wp_version:
                wp_version = wp_version[0]
                ptprinthelper.ptprint(f"File wp-links-opml.php provide version of Wordpress: {wp_version}", "VULN", condition=not self.args.json, indent=4)
                wp_version = wp_version

        # Print meta tags
        if meta_tags:
            meta_tag_result = []
            generator_meta_tags = [tag for tag in meta_tags if tag.get('name') == 'generator']
            for tag in generator_meta_tags:
                # Get wordpress version
                match = re.search(r"WordPress (\d+\.\d+\.\d+)", tag.get("content"), re.IGNORECASE)
                if match:
                    meta_tag_result.append(tag.get("content"))
                    wp_version = match.group(1)

            if meta_tag_result:
                ptprint(f"The metatag 'generator' provides information about WordPress version: {', '.join(meta_tag_result)}", "VULN", condition=not self.args.json, indent=4)
            else:
                ptprint(f"The metatag 'generator' does not provide version of WordPress", "OK", condition=not self.args.json, indent=4)

        if base_response:
            # TODO: Check WP version from source code. Sometimes, plugin version instead of wordpress version can be detected.
            pass

        if rss_response:
            # Get wordpress version
            result = self._get_wp_version_from_rss_feed(response=rss_response)
            wp_version = result if result else wp_version

        # TODO: If you know about more methods, add them ...

        return wp_version

    def _get_wp_version_from_rss_feed(self, response):
        """Retrieve wordpress version from generator tag if possible"""
        try:
            root = ET.fromstring(response.text.strip())
        except:
            ptprinthelper.ptprint(f"Error decoding XML feed", "ERROR", condition=not self.args.json, indent=4)
            return
        generators: list = root.findall(".//generator")
        _wp_version = None
        for generator in generators:
            _wp_version = re.findall(r"wordpress.*?v=(.*)\b", generator.text, re.IGNORECASE)
            _wp_version = _wp_version[0] if _wp_version else None
            if _wp_version:
                break

        if _wp_version:
            ptprinthelper.ptprint(f"RSS feed provide version of Wordpress: {_wp_version}", "VULN", condition=not self.args.json, indent=4)
        else:
            ptprinthelper.ptprint(f"RSS feed does not provide version of Wordpress", "OK", condition=not self.args.json, indent=4)

        return _wp_version

    def fetch_responses_in_parallel(self):

        def fetch(url):
            try:
                return self.http_client.send_request(url=url, method="GET")
            except Exception as e:
                return None

        urls = {
            "rest": self.REST_URL,
            "rss": self.BASE_URL + "/feed",
            "robots": self.BASE_URL + "/robots.txt",
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {name: executor.submit(fetch, url) for name, url in urls.items()}
            responses = {name: future.result() for name, future in futures.items()}
            return responses["rest"], responses["rss"], responses["robots"]
        return rest_response, rss_response, robots_txt_response


def print_api_is_not_available(status_code):
    ptprinthelper.ptprint(f"API is not available" + (f" [{str(status_code)}]" if status_code else ""), "WARNING", condition=True, indent=4)

def _yes_no_prompt(message) -> bool:

        ptprint(" ", "", True)
        ptprint(message + " Y/n", "WARNING", True, end="", flush=True)

        action = input(" ").upper().strip()

        if action == "Y":
            return True
        elif action == "N" or action.startswith("N"):
            return False
        else:
            return True
