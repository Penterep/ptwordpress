import os
import re
import requests
import http.client
from itertools import chain
from queue import Queue
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

from ptlibs import ptprinthelper
from ptlibs.ptprinthelper import ptprint
import ptlibs.tldparser as tldparser

from modules.write_to_file import write_to_file

class SourceEnumeration:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed: bool):
        self.args = args
        self.BASE_URL = base_url
        self.REST_URL = base_url + "/wp-json"
        self.ptjsonlib = ptjsonlib
        self.head_method_allowed = head_method_allowed
        self.extract_result = tldparser.extract(base_url)
        self.domain      = ((self.extract_result.subdomain + ".") if self.extract_result.subdomain else "") + self.extract_result.domain + "." + self.extract_result.suffix
        self.domain2th   = self.extract_result.domain
        self.tld         = self.extract_result.suffix
        self.scheme      = self.extract_result.scheme
        self.full_domain = f"{self.scheme}://{self.domain}"

    def discover_xml_rpc(self):
        """Discover XML-RPC API"""
        xml_data = '''<?xml version="1.0" encoding="UTF-8"?>
        <methodCall>
          <methodName>system.listMethods</methodName>
          <params></params>
        </methodCall>'''
        ptprinthelper.ptprint(f"Testing for xmlrpc.php availability", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        response = requests.post(f"{self.BASE_URL}/xmlrpc.php", proxies=self.args.proxy, verify=False, data=xml_data, allow_redirects=False, headers=self.args.headers)
        ptprinthelper.ptprint(f"[{response.status_code}] {response.url}", "TEXT", condition=not self.args.json, indent=4)
        ptprinthelper.ptprint(f"Script xmlrpc.php is {'available' if response.status_code == 200 else 'not available'}", "VULN" if response.status_code == 200 else "OK", condition=not self.args.json, indent=4)
    

    def check_readme_files(self, themes, plugins):
        """Check for basic readme files at site root and for each theme and plugin."""

        ptprint(f"Check readme files", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        urls: list = []
        for t in themes:
            urls.append(f"{self.BASE_URL}/wp-content/themes/{t}/readme.txt")
        for p in plugins:
            urls.append(f"{self.BASE_URL}/wp-content/plugins/{p}/readme.txt")

        result: list = [self.check_url(url=f"{self.BASE_URL}/readme.html")]
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            result.extend(list(executor.map(self.check_url, urls)))

        ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, end="\r")
        result = [result for result in result if result is not None]

        if all(r is None for r in result):
            if not self.args.read_me:
                ptprinthelper.ptprint(f"No readme files discovered", "OK", condition=not self.args.json, end="\n", flush=True, colortext=False, indent=4, clear_to_eol=True)

        return [result for result in result if result is not None]
    

    def wordlist_discovery(self, wordlist=None, title="files", show_responses=False, search_in_response="", method=None):
        # if wordlist=backup zavolej také funkci, která vytvoří seznam souborů tvořených z názvu domény
        ptprint(f"{title.capitalize()} discovery", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)

        wordlist_file = os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "wordlists", f"{wordlist}.txt")
        with open(wordlist_file, "r") as file:
            lines = file.readlines()  # Načteme všechny řádky najednou
            tested_files = (path.strip() for path in lines if not path.rstrip().endswith('.'))
            tested_files2 = (path.strip() for path in lines if path.rstrip().endswith('.'))

            # if backupfiles are searching, add variations od domain name (example. example_com. example-com.) to wordlist
            if (wordlist == "backups"):
                tested_files2 = chain(tested_files2, ["/" + self.domain2th + "."])
                tested_files2 = chain(tested_files2, ["/" + self.domain2th + "_" + self.tld + "."])
                tested_files2 = chain(tested_files2, ["/" + self.domain2th + "-" + self.tld + "."])
            combinations = (f"{tf}{ext}" for tf in tested_files2 for ext in ['sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj'])
            tested_files = chain(tested_files, combinations)

            if (wordlist == "configs"):
                combinations = ([f"{tf}{ext}" for tf in tested_files2 for ext in ['php_', 'php~', 'bak', 'old', 'zal', 'backup', 'bck', 'php.bak', 'php.old', 'php.zal', 'php.bck', 'php.backup']])
                tested_files = chain(tested_files, combinations)

            urls = [self.scheme + "://"+ self.domain + tested_file for tested_file in tested_files]

            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                result = list(executor.map(self.check_url, urls, [wordlist] * len(urls), [show_responses] * len(urls), [search_in_response] * len(urls), [method] * len(urls)))

        if all(r is None for r in result):
            ptprinthelper.ptprint(f"No {title} discovered", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "", condition=not self.args.json, end="", flush=True, indent=4, clear_to_eol=True)


    def check_url(self, url, wordlist=None, show_responses=False, search_in_response="", method=None):
        method = self.head_method_allowed if method is None else method
        try:
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.head(url, proxies=self.args.proxy, verify=False, allow_redirects=False, headers=self.args.headers) if method == "head" else requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False, headers=self.args.headers)

            # Special checks
            #################
            pattern = r"(?:in\s+)([a-zA-Z]:\\[\\\w.-]+|/[\w./-]+)"
            matches: list = re.findall(pattern, response.text, re.IGNORECASE)

            if (wordlist == "fpd") and matches:
                ptprinthelper.ptprint(f"[{response.status_code}] {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                ptprint("".join(matches), "ADDITIONS", colortext=True, condition=not self.args.json, end="\n", flush=True, indent=8, clear_to_eol=True)
                return url
            else:
                return

            if response.status_code == 200 and search_in_response in response.text.lower():
                if ((wordlist == "dangerous") and "/wp-admin/maint/repair.php" in url) and ("define('WP_ALLOW_REPAIR', true);".lower() in response.text.lower()):
                    return
            #################

                ptprinthelper.ptprint(f"[{response.status_code}] {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                return url
            else:
                if show_responses:
                    ptprinthelper.ptprint(f"[{response.status_code}] {url}", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

        except requests.exceptions.RequestException as e:
            return


    def print_media(self, enumerated_users):
        """Print all media discovered via API"""
        def get_user_slug_or_name(user_id):
            for user in enumerated_users:
                if user["id"] == str(user_id):
                    return user.get("slug") or user.get("name")
            return str(user_id)

        def fetch_page(page):
            try:
                scrapped_media = []
                url = f"{self.BASE_URL}/wp-json/wp/v2/media?page={page}&per_page=100"
                ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
                response = requests.get(url, proxies=self.args.proxy, verify=False, headers=self.args.headers)
                if response.status_code == 200 and response.json():
                    for m in response.json():
                        scrapped_media.append({"source_url": m.get("source_url"), "author_id": m.get("author"), "uploaded": m.get("date_gmt"), "modified": m.get("modified_gmt"), "title": m["title"].get("rendered")})
                    return scrapped_media
            except Exception as e:
                return


        result = []
        source_urls = set()

        # Try get & parse Page 1
        ptprinthelper.ptprint(f"Discovered media (title, author, uploaded, modified, url)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        try:
            response = requests.get(f"{self.BASE_URL}/wp-json/wp/v2/media?page=1&per_page=100", proxies=self.args.proxy, verify=False, allow_redirects=False, headers=self.args.headers)
            for m in response.json():
                result.append({"source_url": m.get("source_url"), "author_id": m.get("author"), "uploaded": m.get("date_gmt"), "modified": m.get("modified_gmt"), "title": m.get("title").get("rendered")})
            if response.status_code != 200:
                raise ValueError
        except Exception as e:
            ptprinthelper.ptprint(f"API is not available [{response.status_code}]", "WARNING", condition=not self.args.json, indent=4)
            return

        # Try get a parse Page 2-99
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            page_range = range(2, 100)  # Pages from 2 to 99
            for i in range(0, len(page_range), 10):  # Send 10 requests to pages together
                futures = {executor.submit(fetch_page, page_range[j]): page_range[j] for j in range(i, min(i + 10, len(page_range)))}
                stop_processing = False
                for future in concurrent.futures.as_completed(futures):
                    data = future.result()
                    if data is None:
                        stop_processing = True
                        break
                    else:
                        result.extend(data)
                if stop_processing:
                    break

        source_urls = set()
        for m in result:
            source_urls.add(m.get("source_url"))

        for media in result:
            ptprinthelper.ptprint(f'{media.get("title")}, {get_user_slug_or_name(media.get("author_id"))}, {media.get("uploaded")}, {media.get("modified")}', "ADDITIONS", colortext=False, condition=not self.args.json, indent=4, clear_to_eol=True)
            ptprinthelper.ptprint(media.get("source_url"), "ADDITIONS", colortext=True, condition=not self.args.json, indent=4, clear_to_eol=True)

        if self.args.output:
            filename = self.args.output + "-media.txt"
            write_to_file(filename, '\n'.join(source_urls))

        return source_urls
    
    def check_directory_listing(self, url_list: list, print_text: bool = True) -> list:
        """Checks for directory listing, returns list of vulnerable URLs."""
        ptprint(f"Directory listing", "TITLE", condition=print_text and not self.args.json, newline_above=True, indent=0, colortext=True)
        vuln_urls = Queue()

        def check_url(url):
            if not url.endswith("/"):
                url += "/"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=print_text and not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            try:
                response = requests.get(url, timeout=5, proxies=self.args.proxy, verify=False, headers=self.args.headers)
                if response.status_code == 200 and "index of /" in response.text.lower():
                    vuln_urls.put(url)  # ✅ Thread-safe zápis
                    ptprinthelper.ptprint(f"{url}", "VULN", condition=print_text and not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                else:
                    ptprinthelper.ptprint(f"{url}", "OK", condition=print_text and not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
            except requests.exceptions.RequestException as e:
                ptprint(f"Error retrieving response from {url}. Reason: {e}", "ERROR", condition=not self.args.json, indent=4)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            executor.map(check_url, url_list)

        return list(vuln_urls.queue)
