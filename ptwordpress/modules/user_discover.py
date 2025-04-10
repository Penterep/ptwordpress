import hashlib
import re
import os
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import requests
import ptlibs.tldparser as tldparser
import defusedxml.ElementTree as ET
from ptlibs import ptprinthelper
from threading import Lock
import json

from modules.file_writer import write_to_file

from modules.plugins.yoast import YoastScraper
from modules.plugins.emails import Emails, get_emails_instance

from ptlibs.http.http_client import HttpClient

from modules.helpers import print_api_is_not_available, load_wordlist_file

class UserDiscover:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed):
        self.ptjsonlib = ptjsonlib
        self.args = args
        self.head_method_allowed = head_method_allowed
        self.BASE_URL = base_url
        self.REST_URL = base_url + "/wp-json"
        self.FOUND_AUTHOR_IDS = set()
        self.ENUMERATED_USERS = []
        self.RESULT_QUERY = Queue()
        self.path_to_user_wordlist = load_wordlist_file("usernames.txt", args_wordlist=self.args.wordlist)
        self.vulnerable_endpoints: set = set()
        self.thread_lock = Lock()
        self.yoast_scraper = YoastScraper(args=self.args)
        self.email_scraper = get_emails_instance(args=self.args)
        self.http_client = HttpClient()

    def run(self):
        methods = [
                self._enumerate_users_by_rss_feed,
                self._enumerate_users_by_author_name,
                self._enumerate_users_by_author_id,
                self.enumerate_by_users,
                self.scrape_users_by_posts,
                self.print_enumerated_users_table,
                self.print_unique_logins,
                self.yoast_scraper.print_result,
            ]

        for method in methods:
            try:
                method()
            except Exception as e:
                continue

    def print_unique_logins(self):
        users = list(self.RESULT_QUERY.queue)
        ptprinthelper.ptprint("Discovered logins", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)
        unique_slugs = sorted(set(user["slug"] for user in users if user["slug"]))
        if not unique_slugs:
            ptprinthelper.ptprint(f"No logins discovered", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            return

        for slug in unique_slugs:
            ptprinthelper.ptprint(slug, "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

        if self.args.output:
            filename = self.args.output + "-usernames.txt"
            write_to_file(filename, '\n'.join(unique_slugs))

    def print_enumerated_users_table(self):
        ptprinthelper.ptprint(f"Discovered users", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        users = list(self.RESULT_QUERY.queue)
        users = self.filter_duplicate_users(users)
        users.sort(key=lambda x: int(x["id"]) if isinstance(x["id"], str) and x["id"].isdigit() else float('inf'))

        if not users:
            ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            return

        try:
            max_id_len   = (max(max(len(str(user["id"])) for user in users), 2) + 2) or 5
            max_slug_len = (max(len(user["slug"]) for user in users)) + 2
            if max_slug_len in [0, 2]:
                max_slug_len = 10
            max_name_len = (max(len(user["name"]) for user in users) + 2)

            ptprinthelper.ptprint(f"ID{' '*(max_id_len-2)}LOGIN{' '*(max_slug_len-5)}NAME", "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True, colortext="TITLE")
            user_lines = list()
            for user in users:
                ptprinthelper.ptprint(f'{user["id"]}{" "*(max_id_len-len(user["id"]))}{user["slug"]}{" "*(max_slug_len-len(user["slug"]))}{user["name"]}', "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
                user_lines.append(f"{user['id']}:{user.get('slug')}:{user['name']}")
        except Exception as e:
            return

        if self.args.output:
            filename = self.args.output + "-users.txt"
            write_to_file(filename, '\n'.join(user_lines))

    def filter_duplicate_users(self, users):
        unique_users = {}

        for user in users:
            name = user['name']
            if name not in unique_users or (unique_users[name]['id'] == '' and user['id'] != ''):
                unique_users[name] = user

        return list(unique_users.values())

    def enumerate_by_users(self) -> list:
        """Enumerate users via /wp/v2/users/?per_page=100&page=<number> endpoint"""
        ptprinthelper.ptprint(f"User enumeration via API users ({self.BASE_URL}/wp-json/wp/v2/users)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        is_vuln = False
        for i in range(1, 100):
            response = self.http_client.send_request(f"{self.REST_URL}/wp/v2/users/?per_page=100&page={i}", method="GET")
            data = self.load_prepare_response_json(response)

            if response.status_code == 200:
                try:
                    if not data:
                        break
                except:
                    break

                for user_object in data:
                    result = {"id": str(user_object.get("id", "")), "slug": user_object.get("slug", ""), "name": user_object.get("name", "")}
                    ptprinthelper.ptprint(f"{result['id']}{' '*(8-len(result['id']))}{result['slug']}{' '*(40-len(result['slug']))}{result['name']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

                    self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, result)
                    author_id = user_object.get("id")
                    if author_id:
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(f"{self.REST_URL}/wp/v2/users/")
                    is_vuln = True
            else:
                break
        if not is_vuln:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))

    def scrape_users_by_posts(self):
        """Retrieve users via /wp-json/wp/v2/posts/?per_page=100&page=<number> endpoint"""
        ptprinthelper.ptprint(f"User enumeration via API posts ({self.BASE_URL}/wp-json/wp/v2/posts)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        enumerated_users = []
        all_posts = []
        seen_users = set()

        def fetch_page(page):
            url = f"{self.REST_URL}/wp/v2/posts/?per_page=100&page={page}"
            try:
                response = self.http_client.send_request(url, method="GET")
                with self.thread_lock:
                    self.email_scraper.parse_emails_from_response(response=response)

                posts: list = self.load_prepare_response_json(response) #response.json() # List
                return posts if response.status_code == 200 else []
            except Exception as e:
                return []

        # Request to first page
        response = self.http_client.send_request(url=f"{self.REST_URL}/wp/v2/posts/?per_page=100&page=1", method="GET")
        data = self.load_prepare_response_json(response)

        if response.status_code != 200:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))
            return
        all_posts.extend(data)
        # Scrape rest of pages
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for page in range(2, 999, 5):
                pages = list(executor.map(fetch_page, range(page, page + 5)))
                all_posts.extend([post for page in pages if page for post in page])

                if any(not posts for posts in pages):  # If any page of the batch returns empty list, stop sending more requests
                    break
            self.yoast_scraper.parse_posts(data=all_posts)

        for post in all_posts:
            user = {"id": str(post.get("author", "")), "slug": "", "name": ""}
            if user["id"] in seen_users:
                continue
            seen_users.add(user["id"])
            user = self.map_user_id_to_slug(user_id=user["id"])
            if not user["slug"] and not user["name"]:
                ptprinthelper.ptprint(f"ID: {user['id']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            else:
                ptprinthelper.ptprint(f"{user['id']}{' '*(8-len(user['id']))}{user['slug']}{' '*(40-len(user['slug']))}{user['name']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            enumerated_users.append(user)

        if enumerated_users:
            for user in enumerated_users:
                self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, user)
        else:
            ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)

    def _enumerate_users_by_author_id(self) -> list:
        """Enumerate users via /?author=<id> query."""
        def check_author_id(author_id: int):
            url = f"{self.BASE_URL}/?author={author_id}"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = self.http_client.send_request(url, method="GET", allow_redirects=False)
            max_length = len(str(self.args.author_range[-1])) - len(str(author_id))
            user_id = response.url.split("=")[-1]
            if response.status_code == 200:
                name_from_title = self._extract_name_from_title(response) # Extracts name from title
                if name_from_title:
                    ptprinthelper.ptprint(f"[{response.status_code}] {url}{' '*max_length} →   {name_from_title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                    return {"id": str(user_id) if user_id.isdigit() else "", "name": name_from_title, "slug": ""}

            elif response.is_redirect:
                location = response.headers.get("Location")
                location = (self.BASE_URL + location) if location and location.startswith("/") else location

                # Extracts username from Location header if possible.
                new_response = self.http_client.send_request(location, method="GET", allow_redirects=False) # For title extraction

                name_from_title = self._extract_name_from_title(new_response)
                if not name_from_title:
                    name_from_title = ""
                re_pattern = r"/author/(.*)/$" # Check if author in redirect
                match = re.search(re_pattern, response.headers.get("location", ""))
                if match:
                    slug = match.group(1)
                    nickname_max_length =  (20 - len(str(name_from_title)))
                    ptprinthelper.ptprint(f"[{response.status_code}] {response.url}{' '*max_length} →   {name_from_title} {' '*nickname_max_length}{slug}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                    return {"id": str(user_id) if user_id.isdigit() else "", "name": name_from_title, "slug": slug}

        futures: list = []
        results: list = []
        ptprinthelper.ptprint(f"User enumeration via author parameter ({self.BASE_URL}/?author=<{self.args.author_range[0]}-{self.args.author_range[1]}>)", "TITLE", condition=not self.args.json, colortext=True, newline_above=False)
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(check_author_id, i) for i in range(self.args.author_range[0], self.args.author_range[1])]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

            if results:
                self.vulnerable_endpoints.add(f"{self.BASE_URL}/?author=<id>")
                for result in results:
                    self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, result)

                    unique_id = result.get("id")
                    self.FOUND_AUTHOR_IDS.add(result.get("id"))
            else:
                ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)

    def _enumerate_users_by_author_name(self) -> list:
        """Dictionary attack via /author/name endpoint"""
        def check_author_name(author_name: str):
            """Thread function"""
            url = f"{self.BASE_URL}/author/{author_name}/"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = self.http_client.send_request(url, method="GET", allow_redirects=False)

            if response.status_code == 200:
                title = self._extract_name_from_title(response)
                ptprinthelper.ptprint(f"[{response.status_code}] {url}    {title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                return {"id": "", "name": title, "slug": author_name}

        results = []
        ptprinthelper.ptprint(f"User enumeration via dictionary ({self.BASE_URL}/author/<name>/)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(check_author_name, author_name) for author_name in self.wordlist_generator(wordlist_path=self.path_to_user_wordlist)]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, result)
                    results.append(result)
            if results:
                self.vulnerable_endpoints.add(f"{self.BASE_URL}/author/<author>/")
            else:
                ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)
            ptprinthelper.ptprint(" ", "TEXT", condition=not self.args.json, clear_to_eol=True)

    def _enumerate_users_via_comments(self):
        for i in range(1, 100):
            url = f"{self.REST_URL}/wp/v2/comments/?per_page=100&page={i}"
            response = self.http_client.send_request(url, method="GET", allow_redirects=True)
            data = self.load_prepare_response_json(response)
            if response.status_code == 200:
                if not data:
                    break
                for comment in data:
                    author_id, author_name, author_slug = comment.get("author"), comment.get("author"), comment.get("author")
                    if author_id:
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(response.url)
            if response.status_code != 200:
                break

    def map_user_id_to_slug(self, user_id):
        """Retrieve user information by user_id"""
        url = f"{self.REST_URL}/wp/v2/users/{user_id}"
        response = self.http_client.send_request(url, method="GET", allow_redirects=True)
        data = self.load_prepare_response_json(response)

        if response.status_code == 200:
            result = {"id": user_id, "slug": data.get("slug"), "name": data.get("name", "")}
            return result
        else:
            result = {"id": user_id, "slug": "", "name": ""}
            return result


    def _enumerate_users_by_rss_feed(self):
        """User enumeration via RSS feed"""
        ptprinthelper.ptprint(f"User enumeration via RSS feed ({self.BASE_URL}/feed)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        rss_authors = set()
        response = self.http_client.send_request(f"{self.BASE_URL}/feed", method="GET")

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
                    ptprinthelper.ptprint(f"{creator}", "VULN", condition=not self.args.json, colortext=False, indent=4)
                    result =  {"id": "", "name": creator, "slug": ""}
                    self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, result)
            if not creators:
                ptprinthelper.ptprint(f"No authors discovered via RSS feed", "OK", condition=not self.args.json, indent=4)
        else:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))

    def load_prepare_response_json(self, response):
        if response.content.startswith(b'\xef\xbb\xbf'):  # BOM for UTF-8
            response.encoding = 'utf-8-sig'  # Set the encoding to handle BOM
        try:
            data = response.json()
            return data
        except json.JSONDecodeError:
            ptprinthelper.ptprint(f"Error parsing response JSON", "ERROR", condition=not self.args.json, indent=4)
            raise


    def parse_feed(self, response):
        rss_authors = set()
        try:
            root = ET.fromstring(response.text.strip())
            # Define the namespace dictionary
            namespaces = {'dc': 'http://purl.org/dc/elements/1.1/'}
            # Find all dc:creator elements and print their text
            creators = root.findall('.//dc:creator', namespaces)
            for creator in creators:
                creator = creator.text.strip()
                if creator not in rss_authors:
                    rss_authors.add(creator)
                    ptprinthelper.ptprint(f"{creator}", "TEXT", condition=not self.args.json, colortext=False, indent=4+4+4)
        except Exception as e:
            ptprinthelper.ptprint(f"Error decoding XML feed, Check content of URL manually.", "ERROR", condition=not self.args.json, indent=4+4+4)
        return rss_authors


    def wordlist_generator(self, wordlist_path: str):
        def load_dynamic_words():
            """Extend default wordlist with dynamic words based on target domain"""
            parsed_url = tldparser.extract(self.BASE_URL)
            dynamic_words =  [
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
            ]
            if parsed_url.subdomain: dynamic_words.append((parsed_url.subdomain + "." + parsed_url.domain + "." + parsed_url.suffix))
            return dynamic_words

        # This happens just once
        dynamic_words = load_dynamic_words()
        for word in dynamic_words:
            # Yield dynamic words
            yield word

        with open(wordlist_path, "r") as f:
            for line in f:
                yield line.strip()  # Yield wordlist

    def _check_if_file_is_readable(self, path):
        """Ensure wordlist contains valid text not binary"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read(1024)  # Read first 1024 chars
                if not content.isprintable():  # If content is not printable
                    raise ValueError(f"File {path} does not appear to be a valid text file.")
        except UnicodeDecodeError:
            raise ValueError(f"File {path} contains non-text (binary) data.")


    def _extract_name_from_title(self, response, base_title=None):
        """Extracts full name from response title"""
        try:
            title = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL).groups()[0]

            email_from_title = re.match(r"([\w\.-]+@[\w\.-]+\.?\w+)", title)
            name_from_title = None
            if email_from_title:
                email_from_title = email_from_title.group(1)

            if not email_from_title:
                name_from_title = re.match(r"^([A-Za-zá-žÁ-Ž0-9._-]+(?:\s[A-Za-zá-žÁ-Ž0-9._-]+)*)\s*[\|\-–—‒―‽·•#@*&,]+", title)
                if name_from_title:
                    name_from_title = name_from_title.group(1)

            if all([email_from_title, name_from_title]) is None:
                return title
            else:
                return email_from_title or name_from_title
        except Exception as e:
            pass

    def update_queue(self, queue, user_data):
        temp_queue = Queue()

        if not user_data.get("id"):
            temp_queue.put(user_data)
            while not queue.empty():
                temp_queue.put(queue.get())
            return temp_queue

        found = False
        while not queue.empty():
            item = queue.get()
            if item.get("id") == user_data.get("id"):
                found = True
                if not item.get("slug") and user_data.get("slug"):
                    item["slug"] = user_data["slug"]
                if not item.get("name") and user_data.get("name"):
                    item["name"] = user_data["name"]
            temp_queue.put(item)

        if not found:
            temp_queue.put(user_data)

        return temp_queue

    def get_user_list(self):
        return list(self.RESULT_QUERY.queue)