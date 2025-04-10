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
from modules.helpers import Helpers, print_api_is_not_available, load_wordlist_file

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
        self.http_client._base_headers        = self.args.headers
        self.helpers                     = Helpers(args=self.args, ptjsonlib=self.ptjsonlib)
        self.BASE_URL, self.REST_URL     = self.helpers.construct_wp_api_url(args.url)

    def run(self, args) -> None:
        """Main method"""
        self.base_response: object = self.helpers._get_base_response(url=self.BASE_URL, instance_to_run=self)

        self.rest_response, self.rss_response, self.robots_txt_response = self.helpers.fetch_responses_in_parallel() # Parallel response retrieval
        self.helpers.check_if_target_is_wordpress(base_response=self.base_response, wp_json_response=None)
        self.helpers._extract_all_links_from_homepage(self.base_response)

        self.is_cloudflare = self.helpers.check_if_behind_cloudflare(base_response=self.base_response)
        self.head_method_allowed: bool      = self.helpers._is_head_method_allowed(url=self.BASE_URL)

        self.target_is_case_sensitive: bool = self.helpers.check_case_sensitivity(url=self.BASE_URL)

        self.helpers._check_if_blocked_by_server(self.base_response.url)

        self.source_discover: object     = SourceDiscover(self.BASE_URL, args, self.ptjsonlib, self.head_method_allowed, self.target_is_case_sensitive)
        self.user_discover: object       = UserDiscover(self.BASE_URL, args, self.ptjsonlib, self.head_method_allowed)
        self.wpscan_api: object          = WPScanAPI(args, self.ptjsonlib)
        self.email_scraper: object       = get_emails_instance(args=self.args)

        meta_tags = self.helpers.extract_and_print_meta_tags(response=self.base_response)
        self.helpers._check_if_blocked_by_server(self.base_response.url)

        self.helpers.parse_site_info_from_rest(rest_response=self.rest_response, base_response=self.base_response, is_cloudflare=self.is_cloudflare)

        self.helpers.collect_favicon_hashes_from_html(response=self.base_response)
        self.helpers.parse_google_identifiers(response=self.base_response)
        self.helpers.extract_and_print_html_comments(response=self.base_response)
        self.wp_version = self.helpers.get_wordpress_version(base_response=self.base_response, rss_response=self.rss_response, meta_tags=meta_tags, head_method_allowed=self.head_method_allowed)

        self.helpers.print_supported_wordpress_versions(wp_version=self.wp_version)
        self.helpers.print_robots_txt(robots_txt_response=self.robots_txt_response)
        self.helpers.process_sitemap(robots_txt_response=self.robots_txt_response)
        self.source_discover.discover_xml_rpc()
        self.helpers._check_if_blocked_by_server(self.base_response.url)

        self.source_discover.wordlist_discovery("admins", title="admin pages", show_responses=True)
        self.source_discover.wordlist_discovery("configs", title="configuration files or pages")
        self.source_discover.wordlist_discovery("dangerous", title="access to dangerous scripts", method="get")
        self.source_discover.wordlist_discovery("settings", title="settings files")
        self.source_discover.wordlist_discovery("fpd", title="Full Path Disclosure vulnerability", method="get")
        self.source_discover.wordlist_discovery("logs", title="log files")
        self.source_discover.wordlist_discovery("managements", title="management interface")
        self.source_discover.wordlist_discovery("informations", title="information pages")
        self.source_discover.wordlist_discovery("statistics", title="statistics")
        self.source_discover.wordlist_discovery("backups", title="backup files or directories")
        self.source_discover.wordlist_discovery("repositories", title="repositories")

        if self.args.readme:
            self.source_discover.wordlist_discovery("readme", title="readme files in root directory")
        else:
            self.source_discover.wordlist_discovery("readme_small_root", title="readme files in root directory")

        plugins = self.source_discover.plugin_themes_discovery(response=self.base_response, content_type="plugin")
        if self.args.plugins:
            self.source_discover.wordlist_discovery("plugins", title="Dictionary plugins")
        themes = self.source_discover.plugin_themes_discovery(response=self.base_response, content_type="theme")

        try:
            self.wpscan_api.run(wp_version=self.wp_version, plugins=plugins, themes=themes)
        except Exception as e:
            pass
        self.helpers.parse_namespaces_from_rest(rest_response=self.rest_response)

        self.user_discover.run()
        self.email_scraper.print_result()

        media_urls: list = self.source_discover.print_media(self.user_discover.get_user_list()) # Scrape all uploaded public media

        # Parse unique directories, add media to it & run directory listing test
        self.http_client._stored_urls.update(open(load_wordlist_file("directories.txt", args_wordlist=self.args.wordlist)).readlines())
        self.http_client._stored_urls.update(media_urls)

        _directories = self.http_client._extract_unique_directories(target_domain=urllib.parse.urlparse(self.BASE_URL).netloc)
        self.source_discover.wordlist_discovery(list(set(_directories)), title="directory listing", search_in_response="index of", method="get")

        if self.args.save_media:
            MediaDownloader(args=self.args).save_media(media_urls)

        self.ptjsonlib.set_status("finished")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

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
            ["-u",  "--url",                    "<url>",                "Connect to URL"],
            ["-rm",  "--readme",                "",                     "Enable readme dictionary attacks"],
            ["-pd",  "--plugins",               "",                     "Enable plugins dictionary attacks"],
            ["-o",  "--output",                 "<file>",               "Save emails, users, logins and media urls to files"],
            ["-sm",  "--save-media",            "<folder>",             "Save media to folder"],
            ["-T",  "--timeout",                "<seconds>",            "Set Timeout"],
            ["-bw",  "--block-wait",            "<miliseconds>",        "Set miliseconds to wait before trying again when blocked"],
            ["-p",  "--proxy",                  "<proxy>",              "Set Proxy"],
            ["-c",  "--cookie",                 "<cookie>",             "Set Cookie"],
            ["-a", "--user-agent",              "<agent>",              "Set User-Agent"],
            ["-d", "--delay",                   "<miliseconds>",        "Set delay before each request"],
            ["-ar", "--author-range",           "<author-range>",       "Set custom range for author enumeration (e.g. 1000-1300)"],
            ["-w", "--wordlist",                "<directory>",          "Set custom wordlist directory"],
            ["-H",  "--headers",                "<header:value>",       "Set Header(s)"],
            ["-wpsk", "--wpscan-key",           "<api-key>",            "Set WPScan API key (https://wpscan.com)"],
            ["-t",  "--threads",                "<threads>",            "Number of threads (default 10)"],
            ["-r",  "--redirects",              "",                     "Follow redirects (default False)"],
            ["-dl",  "--download",              "<directory>",          "Download all versions of Wordpress"],
            ["-gp",  "--get-plugins",           "<filename>",           "Retrieve list of all plugins from wordpress.com api (default plugins.txt in wordlist directory)"],
            ["-C",  "--cache",                  "",                     "Cache HTTP communication"],
            ["-v",  "--version",                "",                     "Show script version and exit"],
            ["-h",  "--help",                   "",                     "Show this help message and exit"],
            ["-j",  "--json",                   "",                     "Output in JSON format"],
        ]
        }]

def parse_args():
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>", allow_abbrev=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u",     "--url", type=str, help="Provide a URL")
    group.add_argument("-dl",    "--download", nargs="?", const=True, help="Download mode")
    group.add_argument("-gp",    "--get-plugins", nargs="?", const=True, help="Get plugins mode")
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
    parser.add_argument("-d",    "--delay",           type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("-T",    "--timeout",         type=int, default=10)
    parser.add_argument("-t",    "--threads",         type=int, default=10)
    parser.add_argument("-v",    "--version",         action='version', version=f'{SCRIPTNAME} {__version__}')

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
