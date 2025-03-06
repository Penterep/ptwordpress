#!/usr/bin/python3
"""
    Copyright (c) 2025 Penterep Security s.r.o.

    ptwordpress - Wordpress Security Testing Tool

    ptwordpress is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptwordpress is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptwordpress.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import concurrent.futures
import re
import csv
import os
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import urllib
import socket
import json
import http.client
import requests

from _version import __version__

import threading
import time
from copy import deepcopy
from queue import Queue
from collections import OrderedDict

from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper, ptnethelper
from ptlibs.ptprinthelper import ptprint


from modules.plugins.emails import Emails, get_emails_instance
from modules.plugins.media_download import MediaDownloader
from modules.user_enumeration import UserEnumeration
from modules.source_enumeration import SourceEnumeration
from modules.wpscan_api import WPScanAPI
from modules.routes_walker import APIRoutesWalker
from modules.dual_output import DualOutput
from modules.plugins.hashes import Hashes

import defusedxml.ElementTree as ET

from bs4 import BeautifulSoup, Comment
from tqdm import tqdm
import socket
import urllib

class PtWordpress:
    def __init__(self, args):
        self.args                        = args
        self.BASE_URL, self.REST_URL     = self.construct_wp_api_url(args.url)
        self.ptjsonlib: object           = ptjsonlib.PtJsonLib()
        self.wpscan_api: object          = WPScanAPI(args, self.ptjsonlib)
        self.base_response: object       = None
        self.rest_response: object       = None
        self.rss_response: object        = None
        self.robots_txt_response: object = None
        self.is_enum_protected: bool     = None # Server returns 429 too many requests error
        self.wp_version: str             = None
        self.routes_and_status_codes     = []

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

    def run(self, args) -> None:
        """Main method"""
        self.base_response: object = self._get_base_response(url=self.BASE_URL)
        self.rest_response, self.rss_response, self.robots_txt_response = self.fetch_responses_in_parallel() # Parallel response retrieval

        self.check_if_target_is_wordpress(base_response=self.base_response, wp_json_response=None)
        self.is_cloudflare = self.check_if_behind_cloudflare(base_response=self.base_response)

        self.head_method_allowed: bool   = self._is_head_method_allowed(url=self.BASE_URL)
        self.SourceFinder: object        = SourceEnumeration(self.BASE_URL, args, self.ptjsonlib, self.head_method_allowed)
        self.UserEnumerator: object      = UserEnumeration(self.BASE_URL, args, self.ptjsonlib, self.head_method_allowed)
        self.email_scraper               = get_emails_instance(args=self.args)

        #self.UserEnumerator.run()
        #input(".")

        self.print_meta_tags(response=self.base_response)
        self.parse_site_info_from_rest(rest_response=self.rest_response)
        self.hashes = Hashes(args)
        self.hashes.get_hashes_from_favicon(response=self.base_response)
        self.parse_google_identifiers(response=self.base_response)
        self.print_html_comments(response=self.base_response)

        self.wp_version = self.get_wordpress_version() # metatags, base response, rss response, .... # TODO: pass as argument.

        self.print_supported_versions(wp_version=self.wp_version) # From API
        self.print_robots_txt(robots_txt_response=self.robots_txt_response)
        self.process_sitemap(robots_txt_response=self.robots_txt_response)

        #self.parse_authentication_from_rest(rest_response=self.rest_response)

        self.SourceFinder.discover_xml_rpc()
        self.SourceFinder.discover_admin_login_page()
        self.SourceFinder.discover_config_files()
        self.SourceFinder.check_dangerous_scripts()
        self.SourceFinder.check_settings_availability()
        self.SourceFinder.check_directory_listing(url_list=[self.BASE_URL + path for path in ["/assets", "/wp-content", "/wp-content/uploads", "/wp-content/plugins", "/wp-content/themes", "/wp-includes", "/wp-includes/js", ]])

        self.SourceFinder.discover_logs()
        self.SourceFinder.discover_database_management_interface()
        self.SourceFinder.discover_phpinfo()
        self.SourceFinder.discover_status_files()
        self.SourceFinder.discover_backups()
        self.SourceFinder.discover_repositories()

        plugins = self.run_plugin_discovery(response=self.base_response)
        themes = self.run_theme_discovery(response=self.base_response)

        _vuln_urls = self.SourceFinder.check_readme_files(themes=themes, plugins=plugins)
        if self.args.read_me:
            self.check_readme_txt(url=self.BASE_URL, vulnerable_urls=_vuln_urls)

        self.wpscan_api.run(wp_version=self.wp_version, plugins=plugins, themes=themes)
        self.parse_namespaces_from_rest(rest_response=self.rest_response)

        #if  self.rest_response:
        self.UserEnumerator.run()
        self.email_scraper.print_result()

        media_urls: list = self.SourceFinder.print_media(self.UserEnumerator.get_user_list()) # Scrape all uploaded public media
        if self.args.save_media:
            MediaDownloader(args=self.args).save_media(media_urls)

        # TODO: Scan all routes, check for routes that are not auth protected (not 401)
        #APIRoutesWalker(self.args, self.ptjsonlib, self.rest_response).run()

        self.ptjsonlib.set_status("finished")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def fetch_responses_in_parallel(self):
        """Funkce pro paralelní načítání odpovědí s ošetřením chyb"""

        def loading_indicator(stop_event):
            """Funkce pro zobrazení točícího se znaku"""
            if self.args.json:
                return
            loading_chars = "|/-\\"
            while not stop_event.is_set():
                for char in loading_chars:
                    sys.stdout.write(f"\r[{char}] Loading .. ")
                    sys.stdout.flush()
                    time.sleep(0.1)
            sys.stdout.write("\r" + " " * 20 + "\r")

        def fetch_response_with_error_handling(future, url):
            """Funkce pro získání výsledku requestu s ošetřením chyb"""
            try:
                return future.result()
            except Exception as e:
                print(f"Error fetching {url}: {e}")
                return None

        #stop_event = threading.Event()
        #loader_thread = threading.Thread(target=loading_indicator, args=(stop_event,), daemon=True)
        #loader_thread.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_rest = executor.submit(self._get_wp_json, url=self.REST_URL)                                                  # example.com/wp-json/
            future_rss = executor.submit(requests.get, self.BASE_URL + "/feed", proxies=self.args.proxy, verify=False)           # example.com/feed
            future_robots = executor.submit(requests.get, self.BASE_URL + "/robots.txt", proxies=self.args.proxy, verify=False)  # example.com/robots.txt
            rest_response = fetch_response_with_error_handling(future_rest, self.REST_URL)
            rss_response = fetch_response_with_error_handling(future_rss, self.BASE_URL + "/feed")
            robots_txt_response = fetch_response_with_error_handling(future_robots, self.BASE_URL + "/robots.txt")
        #stop_event.set()
        #loader_thread.join()
        return rest_response, rss_response, robots_txt_response

    def print_supported_versions(self, wp_version):
        """Print supported wordpress versions"""
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
        response: object = self.load_url("https://api.wordpress.org/core/version-check/1.7/")
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
        if self.wp_version is None:
            ptprint(f"Unknown wordpress version", "WARNING", not self.args.json, indent=4)
        elif self.wp_version not in supported_versions:
            ptprint(f"Target uses unsupported version: {self.wp_version}.", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"{'Target uses latest version: ' if self.wp_version == latest_available_version else 'Target uses supported version: '}" + f"{self.wp_version}", "OK", not self.args.json, indent=4)

    def load_url(self, url, args = None, message: str = None):
        try:
            response, dump = ptmisclib.load_url(url, "GET", headers=self.args.headers, cache=self.args.cache, redirects=self.args.redirects, proxies=self.args.proxy, timeout=self.args.timeout, dump_response=True)
            if message:
                ptprint(f"{message}: {response.url}", "TITLE", not self.args.json, colortext=True, end=" ")
                ptprint(f"[{response.status_code}]", "TEXT", not self.args.json, end="\n")
            return response
        except Exception as e:
            if message:
                ptprint(f"{message}: {args.url}", "TITLE", not self.args.json, colortext=True, end=" ")
                ptprint(f"[err]", "TEXT", not self.args.json)
            self.ptjsonlib.end_error(f"Error retrieving response from server.", self.args.json)

    def print_response_headers(self, response):
        """Print all response headers"""
        ptprint(f"Response headers:", "INFO", not self.args.json, colortext=True)
        for header_name, header_value in response.raw.headers.items():
            ptprint(f"{header_name}: {header_value}", "ADDITIONS", not self.args.json, colortext=True, indent=4)

    def print_meta_tags(self, response):
        """Print all meta tags if text/html in content type"""
        content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "")
        if "text/html" not in content_type:
            return
        soup = BeautifulSoup(response.text, "lxml")
        self.meta_tags = meta_tags = soup.find_all("meta")
        if meta_tags:
            ptprint(f"Meta tags", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
            for meta in meta_tags:
                ptprint(meta, "ADDITIONS", condition=not self.args.json, colortext=True, indent=4)

    def print_html_comments(self, response):
        soup = BeautifulSoup(response.content, 'lxml')
        # Find all comments in the HTML
        comments = {comment for comment in soup.find_all(string=lambda text: isinstance(text, Comment))}
        if comments:
            ptprint(f"HTML comments", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
            for comment in comments:
                comment = str(comment).strip().replace("\n", "\n    ")
                ptprint(comment, "TEXT", condition=not self.args.json, colortext=True, indent=4)
        return comments

    def get_wp_version_from_rss_feed(self, response):
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
            ptprinthelper.ptprint(f"RSS Feed provide version of Wordpress: {_wp_version}", "VULN", condition=not self.args.json, colortext=False, indent=4)
        else:
            ptprinthelper.ptprint(f"RSS Feed does not provide version of Wordpress", "OK", condition=not self.args.json, colortext=False, indent=4)

        return _wp_version

    def get_wordpress_version(self):
        """Retrieve wordpress version from metatags, rss feed, API, ... """
        ptprint(f"Wordpress version", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        svg_badge_response = requests.head(f"{self.BASE_URL}/wp-admin/images/about-release-badge.svg", verify=False, proxies=self.args.proxy, allow_redirects=False)
        if svg_badge_response.status_code == 200:
            ptprinthelper.ptprint(f"{svg_badge_response.url}", "VULN", condition=not self.args.json, colortext=False, indent=4)

        opml_response = requests.get(f"{self.BASE_URL}/wp-links-opml.php", verify=False, proxies=self.args.proxy, allow_redirects=False)
        if opml_response.status_code == 200:
            wp_version = re.findall(r"WordPress.*(\d\.\d\.\d)", opml_response.text)
            if wp_version:
                wp_version = wp_version[0]
                ptprinthelper.ptprint(f"File wp-links-opml.php provide version of Wordpress: {wp_version}", "VULN", condition=not self.args.json, colortext=False, indent=4)

        # Print meta tags
        if self.meta_tags:
            meta_tag_result = []
            generator_meta_tags = [tag for tag in self.meta_tags if tag.get('name') == 'generator']
            for tag in generator_meta_tags:
                # Get wordpress version
                match = re.search(r"WordPress (\d+\.\d+\.\d+)", tag.get("content"), re.IGNORECASE)
                if match:
                    meta_tag_result.append(tag.get("content"))
                    self.wp_version = match.group(1)

            if meta_tag_result:
                ptprint(f"The metatag 'generator' provides information about WordPress version: {', '.join(meta_tag_result)}", "VULN", condition=not self.args.json, indent=4)
            else:
                ptprint(f"The metatag 'generator' does not provide version of WordPress", "OK", condition=not self.args.json, indent=4)


        if self.base_response:
            """TODO: Verze z URL adres ve zdrojovém kódu (zde je někdy uvedena verze WP a jindy verze pluginu, je potřeba vymyslet, jak to rozlišit)"""
            pass


        if self.rss_response:
            # Get wordpress version
            result = self.get_wp_version_from_rss_feed(response=self.rss_response)
            self.wp_version = result if result else self.wp_version

        # TODO: Pokud víš o dalších metodách, tak i ty….
        return self.wp_version

    def print_robots_txt(self, robots_txt_response):
        if robots_txt_response is not None and robots_txt_response.status_code == 200:
            ptprinthelper.ptprint(f"Robots.txt", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
            for line in robots_txt_response.text.splitlines():
                ptprinthelper.ptprint(line, "TEXT", condition=not self.args.json, colortext=False, indent=4)

    def check_if_behind_cloudflare(self, base_response: object):
        """Check if target is behind cloudflare"""
        if any(header.lower() in ["cf-edge-cache", "cf-cache-status", "cf-ray"] for header in base_response.headers.keys()):
            ptprinthelper.ptprint("Target site is behind Cloudflare, results may not be accurate.", "WARNING", condition=not self.args.json, colortext=False, indent=0, newline_above=True)
            return True

    def process_sitemap(self, robots_txt_response):
        """Sitemap tests"""
        ptprint(f"Sitemap", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        try:
            sitemap_response = requests.get(self.BASE_URL + "/sitemap.xml", allow_redirects=False, proxies=self.args.proxy, verify=False)
            if sitemap_response.status_code == 200:
                ptprint(f"Sitemap exists: {sitemap_response.url}", "OK", condition=not self.args.json, indent=4)
            elif sitemap_response.is_redirect:
                ptprint(f"[{sitemap_response.status_code}] {self.BASE_URL + "/sitemap.xml"} -> {sitemap_response.headers.get("location")}", "OK", condition=not self.args.json, indent=4)
            else:
                ptprint(f"[{sitemap_response.status_code}] {sitemap_response.url}", "WARNING", condition=not self.args.json, indent=4)
        except requests.exceptions.RequestException:
            ptprint(f"Error retrieving sitemap from {self.BASE_URL + '/sitemap.xml'}", "WARNING", condition=not self.args.json, indent=4)

        if robots_txt_response.status_code == 200:
            _sitemap_url: list = re.findall(r"Sitemap:(.*)\b", self.robots_txt_response.text, re.IGNORECASE)
            if _sitemap_url:
                ptprint(f"Sitemap{'s' if len(_sitemap_url) > 1 else ''} in robots.txt:", "OK", condition=not self.args.json, indent=4)
                for url in _sitemap_url:
                    ptprint(f"{url}", "TEXT", condition=not self.args.json, indent=4+3)

    def run_theme_discovery(self, response) -> list:
        """Theme discovery"""
        ptprinthelper.ptprint(f"Theme discovery ", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        #_theme_paths: list = re.findall(r"(?<=[\"'])([^\"']*wp-content/themes/(.*?))(?=[\"'])", response.text, re.IGNORECASE)
        _theme_paths: list = re.findall(r"([^\"'()]*wp-content\/themes\/)(.*?)(?=[\"')])", response.text, re.IGNORECASE)
        _theme_paths = sorted(_theme_paths, key=lambda x: x[0]) if _theme_paths else _theme_paths # Sort the list by the first element (full_url)
        themes_names = set()
        path_to_themes = set() # paths used for dictionary attack
        for full_url, relative_path in _theme_paths:
            path_to_theme = full_url.split("/" + relative_path.split("/")[0])[0] + relative_path.split("/")[0]
            if not path_to_theme.startswith("http"): # Relative import 2 absolute, e.g. /wp-content/themes/tm-beans-child/
                if not path_to_theme.startswith("/"):
                    path_to_theme = "/" + path_to_theme
                path_to_theme = self.BASE_URL + path_to_theme

            path_to_themes.add(path_to_theme) # e.g. https://example.com/wp-content/themes/coolTheme-new/
            theme_name = relative_path.split("/")[0]
            themes_names.add(theme_name)

        for theme_name in themes_names:
            ptprint(theme_name, "ADDITIONS", condition=not self.args.json, indent=4)
        if not themes_names:
            ptprint("No theme discovered", "OK", condition=not self.args.json, indent=4)

        # Directory listing test
        vulnerable_urls = []
        for url in path_to_themes:
            result = self.SourceFinder.check_directory_listing(url_list=[url], print_text=False)
            if result:
                vulnerable_urls.extend(result)

        #if vulnerable_urls:
        #    ptprint(f" ", "TEXT", condition=not self.args.json)

        for vuln_url in vulnerable_urls:
            ptprint(f"Theme {vuln_url.split("/")[-2]} ({vuln_url}) is vulnerable to directory listing", "VULN", condition=not self.args.json, indent=4)

        for url in path_to_themes:
            if self.args.read_me:
                self.check_readme_txt(url, print_title=False)

        return list(themes_names)

    def run_plugin_discovery(self, response) -> list:
        """Plugin discovery"""
        ptprint(f"Plugin discovery", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        _plugin_paths: list = re.findall(r"([^\"'()]*wp-content\/plugins\/)(.*?)(?=[\"')])", response.text, re.IGNORECASE)
        _plugin_paths = sorted(_plugin_paths, key=lambda x: x[0]) if _plugin_paths else _plugin_paths # Sort the list by the first element (full_url)
        paths_to_plugins = set() # paths used for dictionary attack
        plugins = dict()
        for full_url, relative_path in _plugin_paths:
            path_to_plugin = full_url.split("/" + relative_path.split("/")[0])[0] + relative_path.split("/")[0]

            if not path_to_plugin.startswith("http"): # Relative import 2 absolute, e.g. /wp-content/plugins/gutenberg/
                if not path_to_plugin.startswith("/"):
                    path_to_plugin = "/" + path_to_plugin
                path_to_plugin = self.BASE_URL + path_to_plugin

            paths_to_plugins.add(path_to_plugin) # e.g. https://example.com/wp-content/plugins/gutenberg/
            plugin_name = relative_path.split("/")[0]
            full_url = full_url + relative_path
            version = full_url.split('?ver')[-1].split("=")[-1] if "?ver" in full_url else "unknown-version"

            # Add plugin to dict structure
            if plugin_name not in plugins:
                plugins[plugin_name] = {}
            if version:
                if version not in plugins[plugin_name]:
                    plugins[plugin_name][version] = []
                plugins[plugin_name][version].append(full_url)

        # Print plugins with merged versions
        for plugin_name, versions in plugins.items():
            # Filter out "unknown-version" from the list of versions
            version_list = [version for version in versions.keys() if version != "unknown-version"]
            version_list.sort(key=lambda version: tuple(map(int, (version.split('.') + ['0']*3)[:3])))

            # If there are no known versions, display "unknown-version"
            if not version_list:
                version_list = ["unknown-version"]

            version_string = ", ".join(version_list)  # Join the versions into a single string

            ptprint(f"{plugin_name} ({version_string})", "TEXT", condition=not self.args.json, indent=4)

            all_urls = []
            for version_urls in versions.values():
                all_urls.extend(version_urls)  # Collect all URLs from different versions

            for url in sorted(set(all_urls)):  # Remove duplicates and sort URLs
                ptprint(url, "ADDITIONS", condition=not self.args.json, indent=8, colortext=True)

        """"
        # Print plugins
        for plugin_name, versions in plugins.items():
            for version, urls in versions.items():
                ptprint(f"{plugin_name} ({version})", "TEXT", condition=not self.args.json, indent=4)
                #ptprint(f"{version}", "TEXT", condition=not self.args.json, indent=4+4)
                for url in urls:
                    ptprint(url, "ADDITIONS", condition=not self.args.json, indent=8, colortext=True)

        if not plugins:
            ptprint("No plugins discovered", "OK", condition=not self.args.json, indent=4)
        """
        # Directory listing test
        vulnerable_urls = []
        for url in paths_to_plugins:
            result = self.SourceFinder.check_directory_listing(url_list=[url], print_text=False)
            if result:
                vulnerable_urls.extend(result)

        if vulnerable_urls:
            ptprint(f" ", "TEXT", condition=not self.args.json)
        for vuln_url in vulnerable_urls:
            ptprint(f"Plugin {vuln_url.split("/")[-2]} ({vuln_url}) is vulnerable to directory listing", "VULN", condition=not self.args.json, indent=4, newline_above=False)

        for url in paths_to_plugins:
            if self.args.read_me:
                self.check_readme_txt(url)
        return list(plugins.keys())


    def _is_head_method_allowed(self, url) -> bool:
        try:
            response = requests.head(url, proxies=self.args.proxy, verify=False)
            return True if response.status_code == 200 else False
        except:
            return False

    def check_readme_txt(self, url, print_title=True, is_vuln=False):
        """Dictionary attack"""
        if print_title:
            ptprint(f"Readme discovery: {url}", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True, clear_to_eol=True)
        path_to_wordlist = os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "modules", "wordlists", "readme.txt")
        vuln_urls = Queue()
        with open(path_to_wordlist) as file:
            wordlist = [line.strip() for line in file.readlines()]

        def check_url(line):
            full_url = f"{url}/{line}"
            ptprinthelper.ptprint(f"[{response.status_code} {http.client.responses.get(response.status_code, '')}] {full_url}", "ADDITIONS", not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            try:
                response = requests.request(method="HEAD" if self.head_method_allowed else "GET", url=full_url, verify=False, proxies=self.args.proxy, allow_redirects=False)
                if response.status_code == 200:
                    ptprinthelper.ptprint(response.url, "VULN", not self.args.json, flush=True, indent=4, clear_to_eol=True)
                    vuln_urls.put(response.url) # Thread safe
                if response.status_code == 429:
                    ptprinthelper.ptprint("Too many requests error.", "WARNING", not self.args.json, flush=True, indent=4, clear_to_eol=True)
            except Exception as e:
                pass

        # Použití ThreadPoolExecutor pro paralelní requesty
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_url, wordlist)

        vuln_urls = list(vuln_urls.queue)
        if is_vuln is False:
            ptprinthelper.ptprint(f"No readme files discovered" if not vuln_urls else " ", "OK" if not vuln_urls else "TEXT", not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

    def _process_meta_tags(self):
        ptprinthelper.ptprint(f"Meta tags", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        soup = BeautifulSoup(self.base_response.text, 'lxml')

        # Find all meta tags with name="generator"
        tags = soup.find_all('meta', attrs={'name': 'generator'})
        if tags:
            for tag in tags:
                ptprinthelper.ptprint(f"{tag.get('content')}", "TEXT", condition=not self.args.json, colortext=False, indent=4)
        else:
            ptprinthelper.ptprint(f"Found none", "TEXT", condition=not self.args.json, colortext=False, indent=4)

    def parse_routes_into_nodes(self, url: str) -> list:
        rest_url = self.REST_URL
        routes_to_test = []

        json_response = self.get_wp_json_response(url)
        for route in json_response["routes"].keys():
            nodes_to_add = []
            main = self.ptjsonlib.create_node_object(node_type="endpoint", properties={"url": url + route})
            routes_to_test.append({"id": main["key"], "url": url + route})

            nodes_to_add.append(main)
            for endpoint in json_response["routes"][route]["endpoints"]:
                endpoint_method = self.ptjsonlib.create_node_object(parent=main["key"], parent_type="endpoint", node_type="method", properties={"name": endpoint["methods"]})
                nodes_to_add.append(endpoint_method)

                if endpoint.get("args"):
                    for parameter in endpoint["args"].keys():
                        nodes_to_add.append(self.ptjsonlib.create_node_object(parent=endpoint_method["key"], parent_type="method", node_type="parameter", properties={"name": parameter, "type": endpoint["args"][parameter].get("type"), "description": endpoint["args"][parameter].get("description"), "required": endpoint["args"][parameter].get("required")}))

            self.ptjsonlib.add_nodes(nodes_to_add)

        return routes_to_test

    def update_status_code_in_nodes(self):
        if self.use_json:
            for dict_ in self.routes_and_status_codes:
                for node in self.ptjsonlib.json_object["results"]["nodes"]:
                    if node["key"] == dict_["id"]:
                        node["properties"].update({"status_code": dict_["status_code"]})

    def parse_authentication_from_rest(self, rest_response):
        ptprinthelper.ptprint(f"Authentication", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        if not self.try_parse_response_json(rest_response=rest_response):
            return
        rest_response = rest_response.json()
        authentication = rest_response.get("authentication", [])
        if authentication:
            for auth in authentication:
                ptprinthelper.ptprint(f"{auth}", "TEXT", condition=not self.args.json, indent=4)

    def parse_namespaces_from_rest(self, rest_response):
        ptprinthelper.ptprint(f"Namespaces (API provided by addons)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        if not self.try_parse_response_json(rest_response=rest_response):
            return
        rest_response = rest_response.json()
        namespaces = rest_response.get("namespaces", [])
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules", "wordlists", "plugin_list.csv"), mode='r') as file:
            csv_reader = csv.reader(file)
            csv_data = list(csv_reader)

        if "wp/v2" in namespaces: # wp/v2 is prerequirement
            #has_v2 = True
            for namespace in namespaces:
                namespace_description = self.find_description_in_csv(csv_data, namespace)
                ptprinthelper.ptprint(f"{namespace} {namespace_description}", "TEXT", condition=not self.args.json, indent=4)


    def try_parse_response_json(self, rest_response):
        try:
            if rest_response is not None and rest_response.status_code != 200:
                raise Exception
            return rest_response.json()
        except Exception as e:
            ptprinthelper.ptprint(f"API is not available [{response.status_code}]", "WARNING", condition=not self.args.json, indent=4)

    def parse_site_info_from_rest(self, rest_response):
        ptprinthelper.ptprint(f"Site info", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        try:
            rest_response.json()
            if rest_response is not None and rest_response.status_code != 200:
                raise Exception
        except Exception as e:
            ptprinthelper.ptprint(f"API is not available [{response.status_code}]", "WARNING", condition=not self.args.json, indent=4)
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
        ptprinthelper.ptprint(f"IP Address: {self.get_target_ip(self.base_response)} {'(Cloudflare)' if self.is_cloudflare else ''}", "TEXT", condition=not self.args.json, indent=4)

    def check_if_target_is_wordpress(self, base_response: object, wp_json_response: object) -> bool:
        """Checks if target runs wordpress, if not script will be terminated."""
        if not any(substring in self.base_response.text.lower() for substring in ["wp-content/", "wp-includes/", "wp-json/"]):
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, indent=0)
            self.ptjsonlib.end_error(f"Target doesn't seem to be running wordpress.", self.args.json)

        # FIXME: Base response check only

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

    def _get_wp_json(self, url):
        """
        Retrieve content from the /wp-json endpoint.

        Args:
            url (str): The base URL of the site to check.

        Returns:
            Response: The HTTP response object of /wp-json endpoint.
        """
        response = ptmisclib.load_url_from_web_or_temp(url, "GET", headers=self.args.headers, proxies=self.args.proxy, data=None, timeout=None, redirects=True, verify=False, cache=self.args.cache)
        try:
            response.json() # If raises error - not wp-json site.
            return response
        except:
            return None
            #self.ptjsonlib.end_error(f"Not a wordpress site or wp-json disabled.", self.args.json)

    def _get_base_response(self, url):
        """Retrieve base response and handle initial redirects"""
        base_response = self.load_url(url=self.BASE_URL, args=self.args, message="Connecting to URL") # example.com/
        self.print_response_headers(response=base_response)
        if base_response.is_redirect:
            self.handle_redirect(base_response, self.args)
        return base_response

    def find_description_in_csv(self, csv_data, text: str):
        # Iterate over the rows in the CSV file
        for row in csv_data:
            if row[0] == text:
                if row[2]:
                    return f"- {row[1]} ({row[2]})"
                else:
                    return f"- {row[1]}"
        return ""

    def _yes_no_prompt(self, message) -> bool:
        if self.args.json:
            return

        ptprint(" ", "", not self.args.json)
        ptprint(message + " Y/n", "WARNING", not self.args.json, end="", flush=True)

        action = input(" ").upper().strip()

        if action == "Y":
            return True
        elif action == "N" or action.startswith("N"):
            return False
        else:
            return True

    def handle_redirect(self, response, args):
        if not self.args.json:
            if True: #self._yes_no_prompt(f"[{response.status_code}] Returned response redirects to {response.headers.get('location', '?')}, follow?"):
                ptprint(f"[{response.status_code}] Returned response redirects to {response.headers.get('location', '?')}, following...", "INFO", not self.args.json, end="", flush=True, newline_above=True)
                ptprint("\n", condition=not self.args.json, end="\n")
                args.redirects = True
                self.BASE_URL = response.headers.get("location")[:-1] if response.headers.get("location").endswith("/") else response.headers.get("location")
                self.REST_URL = self.BASE_URL + "/wp-json"
                self.args = args
                self.run(args=self.args)
                sys.exit(0) # Recurse exit.

def get_help():
    return [
        {"description": ["Wordpress Security Testing Tool"]},
        {"usage": ["ptwordpress <options>"]},
        {"usage_example": [
            "ptwordpress -u https://www.example.com",
        ]},
        {"Info": [
            "If no wordlist option set, default will be used",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",                "Connect to URL"],
            ["-rm",  "--read-me",               "",                     "Enable readme dictionary attacks"],
            ["-o",  "--output",                 "<file>",               "Save emails, users, logins and media urls to files"],
            ["-wpsk", "--wpscan-key",           "<api-key>",            "Set WPScan API key (https://wpscan.com)"],
            ["-sm",  "--save-media",            "<folder>",             "Save media to folder"],
            ["-T",  "--timeout",                "",                     "Set Timeout"],
            ["-p",  "--proxy",                  "<proxy>",              "Set Proxy"],
            ["-c",  "--cookie",                 "<cookie>",             "Set Cookie"],
            ["-a", "--user-agent",              "<agent>",              "Set User-Agent"],
            ["-ar", "--author-range",           "<author-range>",       "Set custom range for author enumeration (e.g. 1000-1300)"],
            ["-wu", "--wordlist-users",         "<user_wordlist>",      "Set Custom wordlist for user enumeration"],
            #["-wu", "--wordlist-users",         "<plugin_wordlist>",   "Set Custom wordlist for plugin enumeration"],
            #["-wu", "--wordlist-sources",       "<source_wordlist>",   "Set Custom wordlist for source enumeration"],
            ["-H",  "--headers",                "<header:value>",       "Set Header(s)"],
            ["-r",  "--redirects",              "",                     "Follow redirects (default False)"],
            ["-C",  "--cache",                  "",                     "Cache HTTP communication"],
            ["-v",  "--version",                "",                     "Show script version and exit"],
            ["-h",  "--help",                   "",                     "Show this help message and exit"],
            ["-j",  "--json",                   "",                     "Output in JSON format"],
        ]
        }]

def parse_range(string: str):
    """Parses range, expected formats are 1-999999, 1 9999"""
    match = re.match(r'(\d+)[- ](\d+)$', string)
    try:
        if not match:
            raise argparse.ArgumentTypeError(f"Error: {string} is not in valid format. Expected range in format 1-99999 or 1 99999.")
        if int(match.group(1)) > int(match.group(2)):
            raise argparse.ArgumentTypeError(f"Error: Provided range is not valid")
        if (int(match.group(1)) > 99999) or (int(match.group(2)) > 99999):
            raise argparse.ArgumentTypeError(f"Error: Provided range is too high")

        if int(match.group(1)) < 1:
            return ( 1, int(match.group(2)) )
        return ( int(match.group(1)), int(match.group(2)) )

    except argparse.ArgumentTypeError as e:
        return (1, 10)


def parse_args():
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",              type=str, required=True)
    parser.add_argument("-p",  "--proxy",            type=str)
    parser.add_argument("-sm",  "--save-media",      type=str)
    parser.add_argument("-wu", "--wordlist-users",   type=str)
    parser.add_argument("-wpsk", "--wpscan-key",     type=str)
    parser.add_argument("-T",  "--timeout",          type=int, default=10)
    parser.add_argument("-t",  "--threads",          type=int, default=20)
    parser.add_argument("-a",  "--user-agent",       type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie",           type=str)
    parser.add_argument("-o",  "--output",           type=str)
    parser.add_argument("-ar", "--author-range",     type=parse_range, default=(1, 10))
    parser.add_argument("-ir", "--id-range",         type=parse_range, default=(1, 10))
    parser.add_argument("-H",  "--headers",          type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-r",  "--redirects",        action="store_true")
    parser.add_argument("-rm",  "--read-me",         action="store_true")
    parser.add_argument("-C",  "--cache",            action="store_true")
    parser.add_argument("-j",  "--json",             action="store_true")
    parser.add_argument("-v",  "--version",          action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    """
    if args.output:
        file = open(args.output, 'a')
        sys.stdout = DualOutput(sys.stdout, file)
    """

    args.timeout = args.timeout if not args.proxy else None
    args.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    args.user_agent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36"
    args.headers = ptnethelper.get_request_headers(args)
    if args.output:
        args.output = os.path.abspath(args.output)

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptwordpress"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtWordpress(args)
    script.run(args)


if __name__ == "__main__":
    main()
