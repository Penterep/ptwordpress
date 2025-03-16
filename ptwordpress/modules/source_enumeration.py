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
    

    def wordlist_discovery(self, wordlist=None, title="files", url_path=None, show_responses=False, search_in_response="", method=None):
        ptprint(f"{title.capitalize()} discovery", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)

        # Variable wordlist can be filename or list of files
        if isinstance(wordlist, str):
            wordlist_file = os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "wordlists", f"{wordlist}.txt")
            with open(wordlist_file, "r") as file:
                lines = file.readlines()
        else:
            lines = wordlist

        tested_files = (path.strip() for path in lines if not path.rstrip().endswith('.'))
        tested_files2 = (path.strip() for path in lines if path.rstrip().endswith('.'))

        # if backupfiles are searching, add variations od domain name (example. example_com. example-com.) to wordlist
        if (wordlist == "backups"):
            tested_files2 = chain(tested_files2, ["/" + self.domain2th + ".", "/" + self.domain2th + "_" + self.tld + ".", "/" + self.domain2th + "-" + self.tld + "."])

        # add files with extensions to testing list for wordlist items endings with "."
        combinations = (f"{tf}{ext}" for tf in tested_files2 for ext in ['sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj'])
        tested_files = chain(tested_files, combinations)

        if (wordlist == "configs"):
            combinations = ([f"{tf}{ext}" for tf in tested_files2 for ext in ['php_', 'php~', 'bak', 'old', 'zal', 'backup', 'bck', 'php.bak', 'php.old', 'php.zal', 'php.bck', 'php.backup']])
            tested_files = chain(tested_files, combinations)

        if (url_path):
            # url_path can be one path or list of paths
            if isinstance(url_path, str):
                urls = [url_path + tested_file for tested_file in tested_files]
            else:
                tested_files_list = list(tested_files)
                urls = ([f"{up}{tf}" for up in url_path for tf in tested_files_list])
        else:
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

            if (wordlist == "fpd"):
                pattern = r"(?:in\s+)([a-zA-Z]:\\[\\\w.-]+|/[\w./-]+)"
                matches: list = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    ptprinthelper.ptprint(f"[{response.status_code}] {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                    ptprint("".join(matches), "ADDITIONS", colortext=True, condition=not self.args.json, end="\n", flush=True, indent=8, clear_to_eol=True)
                    return url
                else:
                    return

            if response.status_code == 200 and search_in_response in response.text.lower():

                if (wordlist == "dangerous") and \
                   (("/wp-admin/maint/repair.php" in url) and ("define('WP_ALLOW_REPAIR', true);".lower() in response.text.lower())) or \
                   (("/wp-admin/maint/wp-signup.php" in url) and ("Registration has been disabled".lower() in response.text.lower())):
                    return

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
