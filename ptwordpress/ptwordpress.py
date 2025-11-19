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
import os
import urllib
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper, ptnethelper
from ptlibs.ptprinthelper import ptprint
from ptlibs.http.http_client import HttpClient

from modules.plugins.emails import get_emails_instance
from modules.plugins.media_downloader import MediaDownloader
from modules.user_discover   import UserDiscover
from modules.source_discover import SourceDiscover
from modules.wpscan_api import WPScanAPI
from modules.routes_walker import APIRoutesWalker
from modules.plugins.hashes import Hashes
from modules.security_tools_identifier import SecurityToolsIdentifier
from modules.helpers import Helpers, print_api_is_not_available, load_wordlist_file

from modules.guessing import Guessing

from modules.wordpress_downloader.wordpres_downloader import WordpressDownloader
from modules.wordpress_downloader.plugins_downloader import WordpressPluginsDownloader

class PtWordpress:
    def __init__(self, args):
        self.args                        = args
        self.ptjsonlib: object           = ptjsonlib.PtJsonLib()
        self.base_response: object       = None
        self.rest_response: object       = None
        self.rss_response: object        = None
        self.robots_txt_response: object = None
        self.is_enum_protected: bool     = None # Server returns 429 too many requests error
        self.wp_version: str             = None
        self.http_client                 = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.http_client._store_urls     = True
        self.http_client.test_fpd        = True
        #self.http_client._base_headers   = self.args.headers
        self.helpers                     = Helpers(args=self.args, ptjsonlib=self.ptjsonlib)

    def run(self, args) -> None:
        """Main method"""
        self.base_response: object  = self.helpers._get_base_response(url=args.url)
        self.BASE_URL, self.REST_URL = self.helpers.construct_wp_api_url(self.base_response.url) # FINAL URLs.

        self.rest_response, self.rss_response, self.robots_txt_response = self.helpers.fetch_responses_in_parallel() # Parallel response retrieval
        self.helpers.check_if_target_is_wordpress(base_response=self.base_response, wp_json_response=None)
        self.helpers._extract_all_links_from_homepage(self.base_response)

        self.is_cloudflare = self.helpers.check_if_behind_cloudflare(base_response=self.base_response)
        self.head_method_allowed: bool      = self.helpers._is_head_method_allowed(url=self.BASE_URL)

        if "TECH" in self.args.tests:
            self.target_is_case_sensitive: bool = self.helpers.check_case_sensitivity(url=self.BASE_URL)
        else:
            self.target_is_case_sensitive = False

        if "TECH" in self.args.tests:
            meta_tags = self.helpers.extract_and_print_meta_tags(response=self.base_response)
        else:
            meta_tags = []

        self.helpers._check_if_blocked_by_server(self.base_response.url)

        self.source_discover: object     = SourceDiscover(self.BASE_URL, args, self.ptjsonlib, self.head_method_allowed, self.target_is_case_sensitive)
        self.user_discover: object       = UserDiscover(self.BASE_URL, args, self.ptjsonlib, self.head_method_allowed)
        self.wpscan_api: object          = WPScanAPI(args, self.ptjsonlib)
        self.email_scraper: object       = get_emails_instance(args=self.args)

        self.helpers._check_if_blocked_by_server(self.base_response.url)

        if "INFO" in self.args.tests:
            self.helpers.parse_site_info_from_rest(rest_response=self.rest_response, base_response=self.base_response, is_cloudflare=self.is_cloudflare)

        if "ICONS" in self.args.tests:
            self.helpers.collect_favicon_hashes_from_html(response=self.base_response)

        if "GOOGLE" in self.args.tests:
            self.helpers.parse_google_identifiers(response=self.base_response)

        if "COMMENTS" in self.args.tests:
            self.helpers.extract_and_print_html_comments(response=self.base_response)

        if "WPS" in self.args.tests or "VERSION" in self.args.tests:
            self.wp_version = self.helpers.get_wordpress_version(base_response=self.base_response, rss_response=self.rss_response, meta_tags=meta_tags, head_method_allowed=self.head_method_allowed)

        if "VERSION" in self.args.tests:
            self.helpers.print_supported_wordpress_versions(wp_version=self.wp_version)

        if "ROBOTS" in self.args.tests:
            self.helpers.print_robots_txt(robots_txt_response=self.robots_txt_response)

        if "SITEMAP" in self.args.tests:
            self.helpers.process_sitemap(robots_txt_response=self.robots_txt_response)

        if "DANGEROUS" in self.args.tests:
            self.source_discover.wordlist_discovery("dangerous", title="access to dangerous scripts", method="get", show_responses=True)

        self.helpers._check_if_blocked_by_server(self.base_response.url)

        if "SETTINGS" in self.args.tests:
            self.source_discover.wordlist_discovery("settings", title="settings files")

        if "FPD" in self.args.tests:
            self.source_discover.wordlist_discovery("fpd", title="Full Path Disclosure vulnerability", method="get")

        if "ADMIN" in self.args.tests or self.args.password:
            is_administration_available = self.source_discover.wordlist_discovery("admins", title="admin pages", show_responses=True)

        if "CONFIG" in self.args.tests:
            self.source_discover.wordlist_discovery("configs", title="configuration files or pages")

        if "LOGS" in self.args.tests:
            self.source_discover.wordlist_discovery("logs", title="log files")

        if "MNGMNT" in self.args.tests:
            self.source_discover.wordlist_discovery("managements", title="management interface")

        if "INFPG" in self.args.tests:
            self.source_discover.wordlist_discovery("informations", title="information pages")

        if "STATS" in self.args.tests:
            self.source_discover.wordlist_discovery("statistics", title="statistics")

        if "BACKUP" in self.args.tests:
            self.source_discover.wordlist_discovery("backups", title="backup files or directories")

        if "REPO" in self.args.tests:
            self.source_discover.wordlist_discovery("repositories", title="repositories")

        if "README" in self.args.tests:
            if self.args.readme:
                self.source_discover.wordlist_discovery("readme", title="readme files in root directory")
            else:
                self.source_discover.wordlist_discovery("readme_small_root", title="readme files in root directory")

        if "PLUGINS" in self.args.tests:
            ptprinthelper.ptprint(f"Security plugins detection", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
            sectoolident = SecurityToolsIdentifier(self.args, self.ptjsonlib)
            results = sectoolident.detect_plugins()
            if not results:
                ptprinthelper.ptprint(f"No security plugin detected", "VULN", condition=not self.args.json, indent=4)
            else:
                for plugin, evidence in results.items():
                    ptprinthelper.ptprint(f"{plugin}", "OK", condition=not self.args.json, indent=4)
                    if self.args.verbose:
                        for item in evidence:
                            ptprinthelper.ptprint(f"{item}", "ADDITIONS", colortext=True, condition=not self.args.json, indent=8)

            plugins: list = self.source_discover.plugin_themes_discovery(response=self.base_response, content_type="plugin")
            if self.args.plugins:
                self.source_discover.wordlist_discovery("plugins", title="Dictionary plugins")
            themes: list = self.source_discover.plugin_themes_discovery(response=self.base_response, content_type="theme")
        else:
            plugins, themes = [], []

        if "WPS" in self.args.tests:
            try:
                self.wpscan_api.run(wp_version=self.wp_version, plugins=plugins, themes=themes)
            except Exception as e:
                pass

        if "API" in self.args.tests:
            self.helpers.parse_namespaces_from_rest(rest_response=self.rest_response)

        self.user_discover.run()
        enumerated_users = self.user_discover.USERS_TABLE.get_users()

        if self.args.password:
            ptprinthelper.ptprint(f"Password guessing attack", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

            if is_administration_available:
                guessing = Guessing(args, self.ptjsonlib)
                usernames = [user.get("slug") for user in self.user_discover.USERS_TABLE.get_users() if user.get("slug")]
                weak_passwords = [line.strip() for line in open(load_wordlist_file("passwords.txt", None), "r", encoding="utf-8")]

                successful_logins, status = guessing.test_login_protection_and_weak_passwords(usernames, weak_passwords)
                if successful_logins:
                    for l, p in successful_logins:
                        ptprinthelper.ptprint(f"{l} : {p}", "VULN", condition=not self.args.json, indent=4)
                else:
                    ptprinthelper.ptprint(f"No accounts guessed", "OK", condition=not self.args.json, indent=4)

                if status == "blocked":
                    ptprinthelper.ptprint(f"Login attempts were blocked by protection mechanisms", "OK", condition=not self.args.json, indent=4)
            else:
                ptprinthelper.ptprint(f"Administration area is not accessible, skipping password attack", "OK", condition=not self.args.json, indent=4)

        if "EMAILS" in self.args.tests:
            self.email_scraper.print_result()

        if "POSTS" in self.args.tests:
            all_posts = self.user_discover._scrape_posts() if not self.user_discover.was_crawled_posts else self.user_discover.all_posts
            extracted = []
            ptprinthelper.ptprint(f"Discovered posts ({'links' if not self.args.verbose else 'link, id, author, date, title'})", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
            for post in all_posts:
                extracted.append({
                    "id": post["id"],
                    "date": post["date"],
                    "modified": post["modified"],
                    "slug": post["slug"],
                    "status": post["status"],
                    "type": post["type"],
                    "link": post["link"],
                    "title": post["title"]["rendered"],
                    "author": post["author"]
                })

                ptprinthelper.ptprint(post["link"], "Text", colortext=False, condition=not self.args.json, indent=4, clear_to_eol=True)
                if self.args.verbose:
                    ptprinthelper.ptprint(f'{post["id"]}, {self.user_discover.USERS_TABLE.get_user_slug_or_name(post["author"])}, {post["date"]}, {post["title"]["rendered"]}', "ADDITIONS", colortext=True, condition=not self.args.json, indent=4, clear_to_eol=True)

            if not all_posts:
                ptprint(f"No posts discovered", "OK", condition=not self.args.json, indent=4)

            if self.args.output:
                self.helpers.save_posts_csv(all_posts, enumerated_users)

        if "MEDIA" in self.args.tests:
            media_urls: list = self.source_discover.print_media(self.user_discover.USERS_TABLE.get_users()) # Scrape all uploaded public media
            # Parse unique directories, add media to it & run directory listing test
            self.http_client._stored_urls.update(media_urls)
            with open(load_wordlist_file("directories.txt", None)) as f:
                entries = [line.strip() for line in f if line.strip()]

            urls = []
            for entry in entries:
                if not entry.startswith("/"):
                    entry = "/" + entry
                urls.append(self.BASE_URL + entry)

            self.http_client._stored_urls.update(urls)

            if self.args.save_media:
                MediaDownloader(args=self.args, ptjsonlib=self.ptjsonlib).save_media(media_urls)
        
        if "EXTURLS" in self.args.tests:
            all_posts = self.user_discover._scrape_posts() if not self.user_discover.was_crawled_posts else self.user_discover.all_posts

            ptprinthelper.ptprint(f"Discovered external links (from posts)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

            for e in sorted(list(self.user_discover.external_links)):
                ptprinthelper.ptprint(e, "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

            if not self.user_discover.external_links:
                ptprinthelper.ptprint("No external links found", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

        if "DIRLIST" in self.args.tests:
            target_domain = urllib.parse.urlparse(self.BASE_URL).netloc
            _directories = self.http_client._extract_unique_directories(target_domain)
            self.source_discover.wordlist_discovery(list(set(_directories)), title="directory listing", search_in_response="index of", method="get")

        self.ptjsonlib.set_status("finished")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)


def get_tests(for_help=False):
    """
    Returns tests either as:
    - for_help=False: list of test names
    - for_help=True: list of lists for help: ["", "", "  TEST", "Description"]
    """
    test_data = [
        ("TECH", "Response headers, interesting headers, case sensitivity, meta tags"),
        ("INFO", "Site information"),
        ("API", "Namespaces provided by addons"),
        ("ICONS", "Favicons discovery"),
        ("GOOGLE", "Google-related identifiers"),
        ("COMMENTS", "HTML comments discovery"),
        ("VERSION", "WordPress version and supported versions"),
        ("ROBOTS", "Robots.txt analysis"),
        ("SITEMAP", "Sitemap discovery"),
        ("DANGEROUS", "Testing for dangerous scripts access"),
        ("ADMIN", "Admin pages discovery"),
        ("CONFIG", "Config files discovery"),
        ("SETTINGS", "Settings files discovery"),
        ("FPD", "Full path disclosure vulnerability discovery"),
        ("LOGS", "Log files discovery"),
        ("MNGMNT", "Management interface discovery"),
        ("INFPG", "Information pages discovery"),
        ("STATS", "Statistics discovery"),
        ("BACKUP", "Backup files or directories discovery"),
        ("REPO", "Repositories discovery"),
        ("DIRLIST", "Test directory listing"),
        ("README", "Readme files in root directory discovery"),
        ("PLUGINS", "Plugin discovery and plugin readmes"),
        ("WPS", "WPScan usage"),
        ("EXTURLS", "Scrape external urls from posts"),
        ("UESRRSS", "User enumeration via RSS feed"),
        ("USERDICT", "User enumeration via dictionary"),
        ("USERPARAM", "User enumeration via author parameter"),
        ("USERAPIU", "User enumeration via API users"),
        ("USERAPIP", "User enumeration via API posts"),
        ("YOAST", "Yoast plugin information"),
        ("EMAILS", "Discovered email addresses from posts"),
        ("MEDIA", "Discovered media details (title, author, uploaded, modified, URL)"),
        ("POSTS", "Discovered posts details"),
    ]
    return [["", "", f"  {k}", v] for k, v in test_data] if for_help else [k for k, _ in test_data]


def get_help():
    return [
        {"description": ["Wordpress Security Testing Tool"]},
        {"usage": ["ptwordpress <options>"]},
        {"usage_example": [
            "ptwordpress -u https://www.example.com",
            "ptwordpress -u https://www.example.com -w ~/mywordlist",
            "ptwordpress -u https://www.example.com -o ./example -sm ./media",
        ]},
        {"Info": [
            "If no wordlist option set, default will be used",
        ]},
        {"options": [
            ["-u",   "--url",                    "<url>",                "Connect to URL"],
            ["-rm",  "--readme",                 "",                     "Enable readme dictionary attacks"],
            ["-pd",  "--plugins",                "",                     "Enable plugins dictionary attacks"],
            ["-ts",  "--tests",                  "<tests>",              "Specify tests:"],
            *get_tests(for_help=True),
            ["","","","",""],
            ["-o",   "--output",                 "<file>",               "Save emails, users, logins and media urls to files"],
            ["-sm",  "--save-media",             "<folder>",             "Save media to folder"],
            ["-T",   "--timeout",                "<seconds>",            "Set Timeout"],
            ["-bw",  "--block-wait",             "<miliseconds>",        "Set miliseconds to wait before trying again when blocked"],
            ["-p",   "--proxy",                  "<proxy>",              "Set Proxy"],
            ["-c",   "--cookie",                 "<cookie>",             "Set Cookie"],
            ["-a",   "--user-agent",             "<agent>",              "Set User-Agent"],
            ["-d",   "--delay",                  "<miliseconds>",        "Set delay before each request"],
            ["-ar",  "--author-range",           "<author-range>",       "Set custom range for author enumeration (default 1-10)"],
            ["-w",   "--wordlist",               "<directory>",          "Set custom wordlist directory"],
            ["-H",   "--headers",                "<header:value>",       "Set Header(s)"],
            ["-wpsk","--wpscan-key",             "<api-key>",            "Set WPScan API key (https://wpscan.com)"],
            ["-pw",  "--password",               "[wordlist]",           "Run password attack on enumerated users"],
            ["-t",   "--threads",                "<threads>",            "Number of threads (default 10)"],
            ["-r",   "--redirects",              "",                     "Follow redirects (default False)"],
            ["-dl",  "--download",               "<directory>",          "Download all versions of Wordpress"],
            ["-gp",  "--get-plugins",            "<filename>",           "Retrieve list of all plugins from wordpress.com api (default plugins.txt in wordlist directory)"],
            ["-C",   "--cache",                  "",                     "Cache HTTP communication"],
            ["-v",   "--version",                "",                     "Show script version and exit"],
            ["-vv",  "--verbose",                "",                     "Enable verbose output"],
            ["-h",   "--help",                   "",                     "Show this help message and exit"],
            ["-j",   "--json",                   "",                     "Output in JSON format"],
        ]
        }]

def validate_wordlist(path):
    if path == "__DEFAULT__":
        return [line.strip() for line in open(load_wordlist_file("passwords.txt", None)) if line.strip()]
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"Wordlist '{path}' does not exist.")
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def parse_args():
    choices = get_tests()
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>", allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u",     "--url", type=str, help="Provide a URL")
    group.add_argument("-dl",    "--download", nargs="?", const=True, help="Download mode")
    group.add_argument("-gp",    "--get-plugins", nargs="?", const=True, help="Get plugins mode")
    parser.add_argument("-ts", "--tests",          type=lambda s: s.upper(), nargs="+", choices=choices, default=choices)
    parser.add_argument("-p",    "--proxy",           type=str)
    parser.add_argument("-sm",   "--save-media",      type=str)
    parser.add_argument("-w",    "--wordlist",        type=str)
    parser.add_argument("-c",    "--cookie",          type=str)
    parser.add_argument("-o",    "--output",          type=str)
    parser.add_argument("-wpsk", "--wpscan-key",      type=str)
    parser.add_argument("-bw",   "--block-wait",      type=int)
    parser.add_argument("-a",    "--user-agent",      type=str, default="Penterep Tools")
    parser.add_argument("-ar",   "--author-range",    type=ptmisclib.parse_range, default=(1, 10))
    parser.add_argument("-ir",   "--id-range",        type=ptmisclib.parse_range, default=(1, 10))
    parser.add_argument("-H",    "--headers",         type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-pd",   "--plugins",         action="store_true", help="Plugins attack")
    parser.add_argument("-r",    "--redirects",       action="store_true")
    parser.add_argument("-rm",   "--readme",          action="store_true")
    parser.add_argument("-C",    "--cache",           action="store_true")
    parser.add_argument("-j",    "--json",            action="store_true")
    parser.add_argument("-vv",    "--verbose",        action="store_true")
    parser.add_argument("-d",    "--delay",           type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("-T",    "--timeout",         type=int, default=10)
    parser.add_argument("-t",    "--threads",         type=int, default=10)
    parser.add_argument("-v",    "--version",         action='version', version=f'{SCRIPTNAME} {__version__}')
    parser.add_argument("-pw", "--password", nargs="?", const="__DEFAULT__", type=validate_wordlist, help="Optional wordlist path or default.")
    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    # Conditional validation: URL must be provided unless -dl or -gp is used
    if not args.url and not (args.download or args.get_plugins):
        sys.exit("The --url argument is required unless --download or --get-plugins is specified.")

    args.timeout = args.timeout if not args.proxy else None
    args.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    args.headers = ptnethelper.get_request_headers(args)
    args.threads = 1 if args.delay != 0 else args.threads # Run in one thread if delay parameter provided.
    if args.output:
        args.output = os.path.abspath(args.output)

    if args.download:
        WordpressDownloader(download_path=args.download, ptjsonlib=ptjsonlib.PtJsonLib())
        sys.exit(0)

    if args.get_plugins:
        WordpressPluginsDownloader(args=args, ptjsonlib=ptjsonlib.PtJsonLib(), download_path=args.get_plugins).run()
        sys.exit(0)

    if args.wordlist:
        args.wordlist = os.path.abspath(args.wordlist)
        if not os.path.isdir(args.wordlist):
            print("Path to wordlist does not exist.")
            sys.exit(1)

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptwordpress"
    args = parse_args()
    script = PtWordpress(args)
    script.run(args)

if __name__ == "__main__":
    main()
