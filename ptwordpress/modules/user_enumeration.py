import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import defusedxml.ElementTree as ET
import ptlibs.tldparser as tldparser
from ptlibs import ptprinthelper

class UserEnumeration:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed):
        self.ptjsonlib = ptjsonlib
        self.args = args
        self.head_method_allowed = head_method_allowed
        self.BASE_URL = base_url
        self.REST_URL = base_url + "/wp-json"
        self.FOUND_AUTHOR_IDS = set()
        self.ENUMERATED_USERS = []
        self.vulnerable_endpoints: set = set() # List of URL spots allowing user enumeration
        self.path_to_user_wordlist = self.get_path_to_wordlist()

    def run(self):
        self._enumerate_users_by_author_id()     # example.com/?author=<author_id>
        self._enumerate_users_by_author_name()   # example.com/author/<author_name> (dictionary attack)
        #self.print_vulnerable_endpoints()
        #return
        self._enumerate_users_by_users()
        self._enumerate_users_by_users_paginator()
        self._enumerate_users_by_posts()
        self.map_user_id_to_slug()
        self._enumerate_users_by_rss_feed()
        self.print_vulnerable_endpoints()

    def _enumerate_users_by_users(self) -> list:
        """Enumerate users via /wp-json/wp/v2/users endpoint"""
        response = requests.get(f"{self.REST_URL}/wp/v2/users", proxies=self.args.proxy, verify=False, allow_redirects=False)
        if response.status_code == 200:
            for user_object in response.json():
                self.FOUND_AUTHOR_IDS.add(user_object.get("id"))
                self.vulnerable_endpoints.add(response.url)

    def _enumerate_users_by_users_paginator(self) -> list:
        """Enumerate users via /wp/v2/users/?per_page=100&page=<number> endpoint"""
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/users/?per_page=100&page={i}", proxies=self.args.proxy, verify=False)
            if response.status_code == 200:
                if not response.json():
                    break
                for post in response.json():
                    author_id, author_name, author_slug = post.get("id"), post.get("name"), post.get("slug")
                    if author_id:
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(f"{self.REST_URL}/wp/v2/users/")
            if response.status_code != 200:
                break

    def _enumerate_users_by_posts(self):
        """Enumerate users via https://example.com/wp-json/wp/v2/posts/?per_page=100&page=<number> endpoint"""
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/posts/?per_page=100&page={i}", allow_redirects=True, proxies=self.args.proxy, verify=False)
            if response.status_code == 200:
                if not response.json():
                    break
                for post in response.json():
                    author_id = post.get("author")
                    if author_id:
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(f"{self.REST_URL}/wp/v2/posts/")
            if response.status_code != 200:
                break


    def _enumerate_users_by_author_id(self) -> list:
        """Enumerate users via /?author=<id> query."""
        def check_author_id(author_id: int):
            url = f"{self.BASE_URL}/?author={author_id}"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, allow_redirects=False, proxies=self.args.proxy, verify=False)
            max_length = len(str(self.args.author_range[-1])) - len(str(author_id))
            if response.status_code == 200:
                # Extracts name from title
                #title = (re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL))
                name_from_title = self._extract_name_from_title(response)
                ptprinthelper.ptprint(f"[{response.status_code}] {url}{' '*max_length} →   {name_from_title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                id_ = response.url.split("=")[-1]
                return int(id_) if id_.isdigit() else None

            elif response.is_redirect:
                location = response.headers.get("Location")
                location = (self.BASE_URL + location) if location and location.startswith("/") else location

                # Extracts username from Location header if possible.
                new_response = requests.get(location, allow_redirects=False, proxies=self.args.proxy, verify=False) # for title extraction
                name_from_title = self._extract_name_from_title(new_response)

                re_pattern = r"/author/(.*)/$" # Check if author in redirect
                match = re.search(re_pattern, response.headers.get("location", ""))
                if match:
                    author_login = match.group(1)
                    nickname_max_length =  (20 - len(str(name_from_title)))
                    ptprinthelper.ptprint(f"[{response.status_code}] {response.url}{' '*max_length} →   {name_from_title} {' '*nickname_max_length}{author_login}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)

        ptprinthelper.ptprint(f"User enumeration: {self.BASE_URL}/?author=<{self.args.author_range[0]}-{self.args.author_range[1]}>", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        futures: list = []
        results: list = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_author_id, i) for i in range(self.args.author_range[0], self.args.author_range[1])]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

            if results:
                self.vulnerable_endpoints.add(f"{self.BASE_URL}/?author=<id>")
                for author_id in results:
                    self.FOUND_AUTHOR_IDS.add(author_id)
            else:
                ptprinthelper.ptprint(f"No names enumerated in {self.args.author_range[0]}-{self.args.author_range[1]} id range", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)
            ptprinthelper.ptprint(" ", "TEXT", condition=not self.args.json, clear_to_eol=True)

    def _enumerate_users_by_author_name(self) -> list:
        """Dictionary attack via /author/name endpoint"""

        def check_author_name(author_name: str):
            """Thread function"""
            url = f"{self.BASE_URL}/author/{author_name}/"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False)

            if response.status_code == 200:
                #title = (re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL) or ["No title"])[1].strip()
                title = self._extract_name_from_title(response)
                #print("TITLE:", title)
                ptprinthelper.ptprint(f"[{response.status_code}] {url}    {title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                return response.url


        results = []
        ptprinthelper.ptprint(f"User enumeration: {self.BASE_URL}/author/<name>/", "TITLE", condition=not self.args.json, colortext=True, newline_above=False)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_author_name, author_name) for author_name in self.wordlist_generator(wordlist_path=self.path_to_user_wordlist)]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
            if results:
                self.vulnerable_endpoints.add(f"{self.BASE_URL}/author/<author>/")
            else:
                ptprinthelper.ptprint(f"No names enumerated via dictionary attack", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)
            ptprinthelper.ptprint(" ", "TEXT", condition=not self.args.json)

    def _enumerate_users_via_comments(self):
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/comments/?per_page=100&page={i}", allow_redirects=True, proxies=self.args.proxy, verify=False)
            if response.status_code == 200:
                if not response.json():
                    break
                for comment in response.json():
                    author_id, author_name, author_slug = comment.get("author"), comment.get("author"), comment.get("author")
                    if author_id:
                        #print(author_id)
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(response.url)
            if response.status_code != 200:
                break

    def map_user_id_to_slug(self):
        def fetch_user_slug(user_id, rest_url, proxy):
            response = requests.get(f"{rest_url}/wp/v2/users/{user_id}", allow_redirects=True, proxies=proxy, verify=False)
            if response.status_code == 200:
                return {"id": user_id, "slug": response.json().get("slug")}
            return None

        ptprinthelper.ptprint(f"Mapping user IDs to slugs:", "TITLE", condition=not self.args.json, colortext=True, newline_above=False)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_user_slug, i, self.REST_URL, self.args.proxy): i for i in sorted(list(self.FOUND_AUTHOR_IDS))}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.ENUMERATED_USERS.append(result)
                    ptprinthelper.ptprint(f"{result['id']}: {result['slug']}", "TEXT", condition=not self.args.json, indent=4)
                else:
                    break
        """
        for i in sorted(list(self.FOUND_AUTHOR_IDS)):
            response = requests.get(f"{self.REST_URL}/wp/v2/users/{i}", allow_redirects=True, proxies=self.args.proxy, verify=False)
            if response.status_code == 200:
                slug = response.json().get("slug")
                self.ENUMERATED_USERS.append({"id": i, "slug": slug})
                ptprinthelper.ptprint(f"{i}: {slug}", "TEXT", condition=not self.args.json, indent=4)
            if response.status_code != 200:
                break
        """

    def _enumerate_users_by_rss_feed(self):
        """User enumeration via RSS feed"""
        ptprinthelper.ptprint(f"User enumeration: {self.BASE_URL}/feed", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        rss_authors = set()
        response = requests.get(f"{self.BASE_URL}/feed", proxies=self.args.proxy, verify=False)
        if response.status_code == 200:
            try:
                root = ET.fromstring(response.text.strip())
            except:
                ptprinthelper.ptprint(f"Error decoding XML feed", "ERROR", condition=not self.args.json, indent=4)
                return
            # Define the namespace dictionary
            namespaces = {'dc': 'http://purl.org/dc/elements/1.1/'}
            # Find all dc:creator elements and print their text
            creators = root.findall('.//dc:creator', namespaces)
            for creator in creators:
                creator = creator.text.strip()
                if creator not in rss_authors:
                    rss_authors.add(creator)
                    ptprinthelper.ptprint(f"{creator}", "TEXT", condition=not self.args.json, colortext=False, indent=4)
        else:
            ptprinthelper.ptprint(f"RSS feed not available", "TEXT", condition=not self.args.json, indent=4)

    def print_vulnerable_endpoints(self):
        ptprinthelper.ptprint(f"Vulnerable endpoints (allowing user enumeration):", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        self.vulnerable_endpoints =  {u[:-1] if u.endswith("/") else u for u in self.vulnerable_endpoints}
        for url in self.vulnerable_endpoints:
                ptprinthelper.ptprint(url, "TEXT", condition=not self.args.json, indent=4)


    def wordlist_generator(self, wordlist_path: str):
        def load_dynamic_words():
            """Extend default wordlist with dynamic words based on target domain"""
            parsed_url = tldparser.extract(self.BASE_URL)
            return [
                parsed_url.domain,                                                      # example
                parsed_url.domain + parsed_url.suffix,                                  # examplecom
                parsed_url.domain + "." + parsed_url.suffix,                            # example.com
                parsed_url.domain + "." + parsed_url.suffix + "-admin",                 # example.com-admin
                parsed_url.domain + "-admin",                                           # example-admin
                "admin@"          +  parsed_url.domain + "." + parsed_url.suffix,       # admin@example.com
                "administrator@"  +  parsed_url.domain + "." + parsed_url.suffix,       # administrator@example.com
                "webmaster@"      +  parsed_url.domain + "." + parsed_url.suffix,       # webmaster@example.com
                "web@"            +  parsed_url.domain + "." + parsed_url.suffix,       # web@example.com,
                "www@"            +  parsed_url.domain + "." + parsed_url.suffix,       # www@example.com,
            ] + [(parsed_url.subdomain + "." + parsed_url.domain + "." + parsed_url.suffix) if parsed_url.subdomain else [], # www.example.com, www.mail.example.com

                ]

        # This happens just once
        dynamic_words = load_dynamic_words()
        for word in dynamic_words:
            # Yield dynamic words
            yield word

        with open(wordlist_path, "r") as f:
            for line in f:
                yield line.strip()  # Yield wordlist


    def get_path_to_wordlist(self):
        """Load correct wordlists"""
        script_dir = os.path.abspath(os.path.dirname(__file__))
        original_path = os.path.join(script_dir, "wordlists", "usernames.txt")

        if not self.args.wordlist_users:
            return original_path
        else:
            if os.path.isfile(self.args.wordlist_users):
                path = os.path.abspath(self.args.wordlist_users)
                try:
                    self._check_if_file_is_readable(path)
                    return path
                except ValueError: # If file is not readable
                    return original_path

    def _check_if_file_is_readable(self, path):
        """Ensure wordlist contains valid text not binary"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read(1024)  # Načte první 1024 znaků
                if not content.isprintable():  # Pokud obsah není tisknutelný
                    raise ValueError(f"File {path} does not appear to be a valid text file.")
        except UnicodeDecodeError:
            raise ValueError(f"File {path} contains non-text (binary) data.")


    def _extract_name_from_title(self, response):
        """Extracts full name from response title"""
        # TODO: Scrape emails
        try:
            title = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL).groups()[0]#[1].strip().split(" ", 2)
            email_from_title = re.match(r"([\w\.-]+@[\w\.-]+\.?\w+)", title)
            email_from_title = email_from_title.group(1) if email_from_title else None
            if not email_from_title:
                name_from_title = re.match(r"^([A-Za-zá-žÁ-Ž0-9._-]+(?:\s[A-Za-zá-žÁ-Ž0-9._-]+)*)\s*[\|\-–—‒―‽·•#@*&]+", title)
                name_from_title = re.match(r"^([A-Za-zá-žÁ-Ž0-9._-]+(?:\s[A-Za-zá-žÁ-Ž0-9._-]+)*)\s*[\|\-–—‒―‽·•#@*&]+", title).group(1)

            return email_from_title or name_from_title
        except Exception as e:
            print(e)
            #return ""