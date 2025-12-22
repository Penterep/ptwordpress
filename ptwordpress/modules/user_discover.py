import re
import os
import json
import urllib

from queue import Queue
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed


import requests
import ptlibs.tldparser as tldparser
import defusedxml.ElementTree as ET

from ptlibs import ptprinthelper
from ptlibs.http.http_client import HttpClient

from modules.file_writer import write_to_file
from modules.plugins.yoast import YoastScraper
from modules.plugins.emails import Emails, get_emails_instance
from modules.helpers import print_api_is_not_available, load_wordlist_file



class UserDiscover:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed):
        self.ptjsonlib = ptjsonlib
        self.args = args
        self.head_method_allowed = head_method_allowed
        self.BASE_URL = base_url
        self.REST_URL = base_url + "/wp-json"
        self.USERS_TABLE = EnumeratedUserTable()
        self.thread_lock = Lock()
        self.vulnerable_endpoints: set = set()

        self.all_posts = []
        self.was_crawled_posts = False
        self.external_links = []
        self.yoast_scraper = YoastScraper(args=self.args)
        self.email_scraper = get_emails_instance(args=self.args)
        self.http_client = HttpClient(self.args, self.ptjsonlib)

    def run(self):
        test_to_method: dict = {
            "UESRRSS": self._enumerate_users_by_rss_feed,
            "USERDICT": self._enumerate_users_by_author_name,     # /author/<username>
            "USERPARAM": self._enumerate_users_by_author_id,      # /?author=<id>
            "USERAPIU": self.enumerate_by_users_endpoint,
            "USERAPIP": self.scrape_users_by_posts,
            "YOAST": self.yoast_scraper.print_result,
        }

        user_tests_ran = False  # track if any user-related test ran

        # Run methods for selected tests
        for test_name, func in test_to_method.items():
            if test_name in set(self.args.tests): # Check if test specified
                try:
                    func()
                    user_tests_ran = True
                except Exception:
                    continue

        # Run the print/output functions only if at least one user test ran
        if user_tests_ran:
            for func in [self.print_unique_logins, self.print_enumerated_users_table]:
                try:
                    func()
                except Exception:
                    continue

    def print_unique_logins(self):
        users = self.USERS_TABLE.get_users()
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
        users = self.USERS_TABLE.get_users()
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

    def enumerate_by_users_endpoint(self) -> list:
        """Enumerate users via /wp/v2/users/?per_page=100&page=<number> endpoint"""
        ptprinthelper.ptprint(f"User enumeration via API users ({self.BASE_URL}/wp-json/wp/v2/users)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        for i in range(1, 100):
            response = self.http_client.send_request(f"{self.REST_URL}/wp/v2/users/?per_page=100&page={i}", method="GET")
            response_data = self.load_prepare_response_json(response)

            if response.status_code != 200:
                print_api_is_not_available(status_code=getattr(response, "status_code", None))
                return

            for user_dict in response_data:
                result = {"id": str(user_dict.get("id", "")), "slug": user_dict.get("slug", ""), "name": user_dict.get("name", "")}
                ptprinthelper.ptprint(f"{result['id']}{' '*(8-len(result['id']))}{result['slug']}{' '*(40-len(result['slug']))}{result['name']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

                self.USERS_TABLE.update_queue(result)
                if user_dict.get("id"):
                    self.vulnerable_endpoints.add(f"{self.REST_URL}/wp/v2/users/")

    def scrape_external_links(self, response):

        text = str(self.load_prepare_response_json(response))

        # find all HTTP/HTTPS URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', text)

        # get the domain of the base URL
        base_domain = urllib.parse.urlparse(self.BASE_URL).netloc

        # filter out only external links
        external_links = list(set([url for url in urls if urllib.parse.urlparse(url).netloc != base_domain]))
        self.external_links.extend(external_links)
        return list(set(external_links))

    def _scrape_posts(self) -> list:
        """Scrapes and returns all site posts"""
        posts: list = []
        self.was_crawled_posts = True
        # Get first page of posts
        response = self.http_client.send_request(url=f"{self.REST_URL}/wp/v2/posts/?per_page=100&page=1", method="GET")

        # Check stability
        if response.status_code != 200:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))
            return

        # Scrape mails
        self.email_scraper.parse_emails_from_response(response=response)

        # scrape links
        self.scrape_external_links(response=response)

        # Add to posts
        posts.extend(self.load_prepare_response_json(response))

        def fetch_page(page):
            url = f"{self.REST_URL}/wp/v2/posts/?per_page=100&page={page}"
            try:
                response = self.http_client.send_request(url, method="GET")
                ptprinthelper.ptprint(url, "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
                with self.thread_lock:
                    self.email_scraper.parse_emails_from_response(response=response)
                    self.scrape_external_links(response=response)


                posts: list = self.load_prepare_response_json(response) #response.json() # List
                return posts if response.status_code == 200 else []
            except Exception as e:
                return []

        # Scrape rest of posts in paralell
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for start_page in range(2, 999, 5):
                # Define the current batch of pages
                batch_pages = range(start_page, start_page + 8)

                # Fetch all pages in this batch in parallel
                batch_results = list(executor.map(fetch_page, batch_pages))

                # Flatten results and add to posts
                for page_posts in batch_results:
                    if page_posts:
                        posts.extend(page_posts)

                 # Stop if any page returned no posts
                if any(len(page_posts) == 0 for page_posts in batch_results):
                    break

        # Run Yoast Scanner againsts all posts.
        if "YOAST" in self.args.tests:
            self.yoast_scraper.parse_posts(data=posts)

        return posts


    def scrape_users_by_posts(self):
        """Retrieve users via /wp-json/wp/v2/posts/?per_page=100&page=<number> endpoint"""
        ptprinthelper.ptprint(f"User enumeration via API posts ({self.BASE_URL}/wp-json/wp/v2/posts)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        self.all_posts = self._scrape_posts() if not self.was_crawled_posts else self.all_posts

        # Collect all new user IDs
        ids_to_enumerate = set()
        for post in self.all_posts:
            user_id = str(post.get("author", ""))
            self.USERS_TABLE.update_queue({"id": user_id, "slug": "", "name": ""})
            #if self.USERS_TABLE.needs_enumeration(user_id):
            ids_to_enumerate.add(user_id)

        enumerated_users = []
        space = max(1, len(str(max(ids_to_enumerate, default=1))))
        for uid in ids_to_enumerate:
            #user = self.enumerate_via_author_id_endpoint(uid, space=space)
            user = self.check_author_id(uid)

            if not user["slug"] and not user["name"]:
                user = self.enumerate_via_users_id_endpoint(user_id=uid)

            if not user["slug"] and not user["name"]:
                ptprinthelper.ptprint(f"ID: {user['id']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

            enumerated_users.append(user)

        if enumerated_users:
            for user in enumerated_users:
                self.USERS_TABLE.update_queue(user)

        else:
            ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)

    def enumerate_via_users_id_endpoint(self, user_id, max_length):
        """Retrieve user information by users/<id> endpoint"""
        url = f"{self.REST_URL}/wp/v2/users/{user_id}"
        response = self.http_client.send_request(url, method="GET", allow_redirects=True)

        data = self.load_prepare_response_json(response)

        if response.status_code == 200:
            result = {"id": user_id, "slug": data.get("slug"), "name": data.get("name", "")}
            if data.get("slug") or data.get("name"):
                #ptprinthelper.ptprint(f"ID: {user_id}{' '*max_length}   → {' '*max_length} →   {data.get("slug")}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                ptprinthelper.ptprint(f"ID: {author_id}{' '*max_length}   → {url}{' '*max_length} →   {data.get('name', '')} {' '*nickname_max_length}{data.get('slug', '')}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
            return result
        else:
            result = {"id": user_id, "slug": "", "name": ""}
            return result

    def check_author_id(self, author_id: int):
        url = f"{self.BASE_URL}/?author={author_id}"
        ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
        response = self.http_client.send_request(url, method="GET", allow_redirects=False)

        username_from_response = self._find_author_username(response)
        max_length = len(str(self.args.author_range[-1])) - len(str(author_id))
        user_id = response.url.split("=")[-1]
        if response.status_code == 200:
            name_from_title = self._extract_name_from_title(response) # Extracts name from title
            if name_from_title:
                nickname_max_length =  (20 - len(str(name_from_title)))
                ptprinthelper.ptprint(f"[{response.status_code}] {url}{' '*max_length} →   {name_from_title} {' '*nickname_max_length}{username_from_response}", "VULN", condition=not self.args.json, indent=4)
                return {"id": str(user_id) if user_id.isdigit() else "", "name": name_from_title, "slug": username_from_response}

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
                ptprinthelper.ptprint(f"[{response.status_code}] {response.url}{' '*max_length} →   {name_from_title} {' '*nickname_max_length}{slug}", "VULN", condition=not self.args.json, indent=4)
                return {"id": str(user_id) if user_id.isdigit() else "", "name": name_from_title, "slug": slug}

    def _enumerate_users_by_author_id(self) -> list:
        """Enumerate users via /?author=<id> query."""
        results: list = []
        ptprinthelper.ptprint(f"User enumeration via author parameter ({self.BASE_URL}/?author=<{self.args.author_range[0]}-{self.args.author_range[1]}>)", "TITLE", condition=not self.args.json, colortext=True, newline_above=False)
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(self.check_author_id, i) for i in range(self.args.author_range[0], self.args.author_range[1])]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

            if results:
                self.vulnerable_endpoints.add(f"{self.BASE_URL}/?author=<id>")
                for result in results:
                    self.USERS_TABLE.update_queue(result)
            else:
                ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)

    def _find_author_username(self, response) -> str:
        """Find author in response.text"""
        text = response.text
        # 1) author/<name>/feed/
        m = re.search(r"author/([^/]+)/feed/", text, re.IGNORECASE)
        if m:
            return m.group(1)

        # 2) author-<username>  (alphanumeric + _ + -)
        matches = re.findall(r"author-([a-zA-Z_-]+)", text, re.IGNORECASE)
        if matches:
            return matches[0]

        return ""

    def _find_author_id(self, response) -> str:
        """Find author id in response"""
        #m = re.search(r"author-(\d+)", response.text)
        m = list(re.finditer(r"author-(\d+)", response.text))
        if m:
            return m[-1].group(1)
        return ""

    def _enumerate_users_by_author_name(self) -> list:
        """Dictionary attack via /author/name endpoint"""

        def check_author_name(author_name: str):
            url = f"{self.BASE_URL}/author/{author_name}/"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = self.http_client.send_request(url, method="GET", allow_redirects=False)

            if response.status_code == 200:
                title = self._extract_name_from_title(response)
                user_id = self._find_author_id(response)
                spaces = max(1, formatting_length - len(author_name))
                ptprinthelper.ptprint(f"[{response.status_code}] {url}{' ' * spaces}{title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                return {"id": user_id, "name": title, "slug": author_name}

        results = []
        ptprinthelper.ptprint(f"User enumeration via dictionary ({self.BASE_URL}/author/<name>/)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            usernames_wordlist_path: str = load_wordlist_file("usernames.txt", args_wordlist=self.args.wordlist)
            formatting_length = max((len(word.strip()) for word in open(usernames_wordlist_path)), default=1)
            futures = [executor.submit(check_author_name, author_name) for author_name in self.wordlist_generator(wordlist_path=usernames_wordlist_path)]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    self.USERS_TABLE.update_queue(result)
                    results.append(result)

        if results:
            self.vulnerable_endpoints.add(f"{self.BASE_URL}/author/<author>/")
            ptprinthelper.ptprint(" ", "TEXT", condition=not self.args.json, clear_to_eol=True, end="")
        else:
            ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True, end="\n\n")

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
                        self.vulnerable_endpoints.add(response.url)
            if response.status_code != 200:
                break

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
                    self.USERS_TABLE.update_queue(result)
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


class EnumeratedUserTable:
    def __init__(self):
        self.RESULT_QUERY = Queue()

    def get_users(self):
        """
        Returns a list of users currently in the queue.
        """
        return list(self.RESULT_QUERY.queue)

    def update_queue(self, user_data: dict) -> None:
        """
        Updates the queue with a user entry.

        Rules:
            1. If a user with the same ID exists, fill in missing 'name' or 'slug'.
            2. Remove any entries with empty ID if they duplicate an existing 'name' or 'slug'.
            3. Add the new user only if no duplicate exists.
        """
        temp_queue = Queue()
        user_id = user_data.get("id")
        user_name = user_data.get("name")
        user_slug = user_data.get("slug")

        found = False
        duplicate = False

        while not self.RESULT_QUERY.empty():
            item = self.RESULT_QUERY.get()

            # Update existing ID
            if user_id and item.get("id") == user_id:
                found = True
                if not item.get("name") and user_name:
                    item["name"] = user_name
                if not item.get("slug") and user_slug:
                    item["slug"] = user_slug

            # Detect duplicates by name or slug
            if (user_name and user_name == item.get("name")) or (user_slug and user_slug == item.get("slug")):
                duplicate = True

            # Only keep item if it’s not an empty ID duplicate
            if not (item.get("id") == "" and duplicate):
                temp_queue.put(item)

        # Add new entry only if it’s not a duplicate and not found by ID
        if not duplicate and not found:
            temp_queue.put(user_data)

        self.RESULT_QUERY = temp_queue

    def needs_enumeration(self, user_id: str) -> bool:
        """
        Returns True if the queue contains an entry with the given user_id
        but is missing 'slug' or 'name'.
        """
        for item in self.RESULT_QUERY.queue:
            if item.get("id") == user_id:
                if not item.get("slug") or not item.get("name"):
                    return True
                else:
                    return False
        return False


    def get_user_slug_or_name(self, user_id):
        """
        Returns the 'slug' if present, otherwise 'name', for the given user_id.
        If neither exists, returns the user_id itself.
        """
        for user in self.RESULT_QUERY.queue:
            if str(user.get("id")) == str(user_id):
                return user.get("slug") or user.get("name") or str(user_id)
        return str(user_id)