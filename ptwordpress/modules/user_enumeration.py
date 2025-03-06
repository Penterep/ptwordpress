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

from modules.write_to_file import write_to_file
#from modules.rss_feed_enumerator import RssFeedEnumerator

from modules.plugins.yoast import YoastScraper
from modules.plugins.emails import Emails, get_emails_instance

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

        self.thread_lock = Lock()
        self.yoast_scraper = YoastScraper(args=self.args)
        self.RESULT_QUERY = Queue()

        self.email_scraper = get_emails_instance(args=self.args)

        #self.rss_feed_enumerator = RssFeedEnumerator(base_url=self.BASE_URL, args=self.args)
        #self.rss_feed_enumerator.run()

    def run(self):
        self._enumerate_users_by_rss_feed()
        self._enumerate_users_by_author_name()        # example.com/author/<author> (dictionary attack)
        self._enumerate_users_by_author_id()          # example.com/?author=<id> (range attack)
        self.enumerate_by_users()    # example.com/wp-json/wp/v2/users?page=<id>&per_page=100

        self._enumerate_users_by_posts()
        #self.map_user_id_to_slug()
        self.print_enumerated_users_table()           #
        self.print_unique_logins()
        #self.print_vulnerable_endpoints()
        self.yoast_scraper.print_result()

    def print_unique_logins(self):
        users = list(self.RESULT_QUERY.queue)
        ptprinthelper.ptprint("Discovered logins", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)
        if not users:
            ptprinthelper.ptprint(f"No logins discovered", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            return

        unique_slugs = sorted(set(user["slug"] for user in users if user["slug"]))

        for slug in unique_slugs:
            ptprinthelper.ptprint(slug, "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

        if self.args.output:
            filename = self.args.output + "-usernames.txt"
            write_to_file(filename, '\n'.join(unique_slugs))

    def print_enumerated_users_table(self):
        ptprinthelper.ptprint(f"Enumerated users", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        users = self.remove_duplicates(list(self.RESULT_QUERY.queue))
        # Seřaď podle ID (s ošetřením prázdných hodnot a správnou kontrolou typu)
        users.sort(key=lambda x: int(x["id"]) if isinstance(x["id"], str) and x["id"].isdigit() else float('inf'))

        if not users:
            ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            return

        # Krok 1: Najít maximální délku pro každý sloupec
        try:
            max_id_len   = (max(max(len(str(user["id"])) for user in users), 2) + 2) or 5
            max_slug_len = (max(len(user["slug"]) for user in users) + 2) or 40
            max_name_len = (max(len(user["name"]) for user in users) + 2)


            ptprinthelper.ptprint(f"ID{' '*(max_id_len-2)}LOGIN{' '*(max_slug_len-5)}NAME", "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True, colortext="TITLE")
            #ptprinthelper.ptprint("-" * (max_id_len + max_name_len + max_slug_len + 6), "TEXT", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True)
            user_lines = list()
            for user in users:
                ptprinthelper.ptprint(f'{user["id"]}{" "*(max_id_len-len(user["id"]))}{user["slug"]}{" "*(max_slug_len-len(user["slug"]))}{user["name"]}', "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
                #ptprinthelper.ptprint(f"{user['id']}{' ' * (max_id_len - len(user['id']))}{user['name']}{' ' *(max_name_len - len(user['name']))}{user['slug']}{' ' *(max_slug_len - len(user['slug']))}", "TEXT", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True)
                user_lines.append(f"{user['id']}:{user.get('slug')}:{user['name']}")
        except Exception as e:
            print(e)
            return

        if self.args.output:
            filename = self.args.output + "-users.txt"
            #if "." in self.args.output:
            #    splitted = self.args.output.split(".")
            #    filename = f"{splitted[0]}-users.{splitted[-1]}"
            write_to_file(filename, '\n'.join(user_lines))


    def enumerate_by_users(self) -> list:
        """Enumerate users via /wp/v2/users/?per_page=100&page=<number> endpoint"""
        #_range = f"<{self.args.author_range[0]}-{self.args.author_range[1]}>"
        ptprinthelper.ptprint(f"User enumeration via API users ({self.BASE_URL}/wp-json/wp/v2/users)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        is_vuln = False
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/users/?per_page=100&page={i}", proxies=self.args.proxy, verify=False)
            if response.status_code == 200:
                if not response.json():
                    break

                for user_object in response.json():
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
            ptprinthelper.ptprint(f"API is not available [{response.status_code}]", "WARNING", condition=not self.args.json, indent=4)

    def _enumerate_users_by_posts(self):
        """Enumerate users via https://example.com/wp-json/wp/v2/posts/?per_page=100&page=<number> endpoint"""
        ptprinthelper.ptprint(f"User enumeration via API posts ({self.BASE_URL}/wp-json/wp/v2/posts)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        def fetch_page(page):
            """Thread function to fetch a single page of posts"""
            try:
                #ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
                url = f"{self.REST_URL}/wp/v2/posts/?per_page=100&page={page}"
                response = requests.get(url, proxies=self.args.proxy, verify=False)
                posts: dict = response.json()
                results = []

                if response.status_code != 200 or not posts:
                    return None

                with self.thread_lock:
                    self.yoast_scraper.parse_posts(data=response.json())
                    self.email_scraper.parse_emails_from_response(response=response)

                for post in posts:
                    result = {
                        "id": str(post.get("author", "")),
                        "slug": "",
                        "name": ""
                    }

                    with self.thread_lock:
                        if result["id"] in seen_users:
                            continue
                        seen_users.add(result["id"])

                    if result["id"]:
                        result = self.map_user_id_to_slug(user_id=result["id"])
                        if not result["slug"] and not result["name"]:
                            ptprinthelper.ptprint(f"{result['id']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
                        else:
                            ptprinthelper.ptprint(f"{result['id']}{' '*(8-len(result['id']))}{result['slug']}{' '*(40-len(result['slug']))}{result['name']}", "VULN", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

                        results.append(result)
                return results
            except Exception as e:
                return None

        results = []
        seen_users = set()
        with ThreadPoolExecutor(max_workers=10) as executor:
            page_range = range(1, 100)
            for i in range(0, len(page_range), 10):  # Posíláme po 10 stránkách najednou
                futures = {executor.submit(fetch_page, page_range[j]): page_range[j] for j in range(i, min(i + 10, len(page_range)))}
                # Zpracování výsledků
                for future in as_completed(futures):
                    result = future.result()  # Opraveno na `result` místo `results`
                    if result:
                        for r in result:
                            self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, r)
                    else:
                        # Když dostaneme None, znamená to problém s odpovědí, přerušujeme.
                        return
        if not results:
            ptprinthelper.ptprint(f"No users discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)

    def _enumerate_users_by_author_id(self) -> list:
        """Enumerate users via /?author=<id> query."""
        def check_author_id(author_id: int):
            url = f"{self.BASE_URL}/?author={author_id}"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, allow_redirects=False, proxies=self.args.proxy, verify=False)
            max_length = len(str(self.args.author_range[-1])) - len(str(author_id))
            user_id = response.url.split("=")[-1]
            if response.status_code == 200:
                # Extracts name from title
                #title = (re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL))
                name_from_title = self._extract_name_from_title(response)
                if name_from_title:
                    ptprinthelper.ptprint(f"[{response.status_code}] {url}{' '*max_length} →   {name_from_title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                    return {"id": str(user_id) if user_id.isdigit() else "", "name": name_from_title, "slug": ""}

            elif response.is_redirect:
                location = response.headers.get("Location")
                location = (self.BASE_URL + location) if location and location.startswith("/") else location

                # Extracts username from Location header if possible.
                new_response = requests.get(location, allow_redirects=False, proxies=self.args.proxy, verify=False) # for title extraction
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
        with ThreadPoolExecutor(max_workers=10) as executor:
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
            #ptprinthelper.ptprint(" ", "TEXT", condition=not self.args.json, clear_to_eol=True)

    def _enumerate_users_by_author_name(self) -> list:
        """Dictionary attack via /author/name endpoint"""
        def check_author_name(author_name: str):
            """Thread function"""
            url = f"{self.BASE_URL}/author/{author_name}/"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False)

            if response.status_code == 200:
                title = self._extract_name_from_title(response)
                ptprinthelper.ptprint(f"[{response.status_code}] {url}    {title}", "VULN", condition=not self.args.json, indent=4, clear_to_eol=True)
                return {"id": "", "name": title, "slug": author_name}

        results = []
        ptprinthelper.ptprint(f"User enumeration via dictionary ({self.BASE_URL}/author/<name>/)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        with ThreadPoolExecutor(max_workers=10) as executor:
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

    def map_user_id_to_slug(self, user_id):
        """Retrieve user information by user_id"""
        response = requests.get(f"{self.REST_URL}/wp/v2/users/{user_id}", allow_redirects=True, proxies=self.args.proxy, verify=False)
        if response.status_code == 200:
            result = {"id": user_id, "slug": response.json().get("slug"), "name": response.json().get("name", "")}
            return result
        else:
            result = {"id": user_id, "slug": "", "name": ""}
            return result


    def _enumerate_users_by_rss_feed(self):
        """User enumeration via RSS feed"""
        ptprinthelper.ptprint(f"User enumeration via RSS Feed ({self.BASE_URL}/feed)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
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
                    ptprinthelper.ptprint(f"{creator}", "VULN", condition=not self.args.json, colortext=False, indent=4)
                    result =  {"id": "", "name": creator, "slug": ""}
                    self.RESULT_QUERY = self.update_queue(self.RESULT_QUERY, result)
            if not creators:
                ptprinthelper.ptprint(f"No authors discovered via RSS feed", "OK", condition=not self.args.json, indent=4)
        else:
            ptprinthelper.ptprint(f"API is not available [{response.status_code}]", "WARNING", condition=not self.args.json, indent=4)

    def parse_feed(self, response):
        """TODO:"""
        #ptprinthelper.ptprint(f"{url}", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
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
            print(e)
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
            print(e)
            #return ""

    def update_queue(self, queue, user_data):
        # Dočasně vyprázdni frontu
        temp_queue = Queue()

        # Pokud ID není uvedeno nebo je prázdné, přidej nový záznam rovnou
        if not user_data.get("id"):
            temp_queue.put(user_data)
            while not queue.empty():
                temp_queue.put(queue.get())
            return temp_queue

        # Projdi původní frontu a zkopíruj položky do dočasné fronty
        found = False  # Flag, který nám pomůže zjistit, zda jsme našli záznam s tímto ID
        while not queue.empty():
            item = queue.get()
            if item.get("id") == user_data.get("id"):
                # Pokud položka s tímto ID existuje, slouč ji
                found = True
                # Aktualizuj pouze ty hodnoty, které jsou prázdné
                if not item.get("slug") and user_data.get("slug"):
                    item["slug"] = user_data["slug"]
                if not item.get("name") and user_data.get("name"):
                    item["name"] = user_data["name"]
            # Přidej upravený (nebo nezměněný) záznam do dočasné fronty
            temp_queue.put(item)

        # Pokud jsme nenašli záznam, přidej nový
        if not found:
            temp_queue.put(user_data)

        # Nahradíme původní frontu
        return temp_queue

    def remove_duplicates(self, objects):
        """
        Remove objects from the list that have a duplicate 'name' and do not contain
        additional information (i.e., empty 'id' and 'slug').

        The function checks for objects that have the same 'name'. If an object has the
        same name as another, but it lacks an 'id' and 'slug', it is considered a duplicate
        and is excluded from the result.

        Args:
            objects (list of dict): A list of dictionaries where each dictionary represents
                                    an object with keys like 'id', 'name', and 'slug'.

        Returns:
            list of dict: A list of dictionaries with duplicates removed, keeping only objects
                        that have either 'id' or 'slug', or if the name is unique.
        """
        seen_names = {}  # Dictionary to store the first object with an 'id' or 'slug' for each name
        result = []

        for obj in objects:
            name = obj['name']

            # If the object has an 'id' or 'slug', we add it to the result
            if obj['id'] or obj['slug']:
                seen_names[name] = obj

        # Now add only the first occurrence of each name (those with 'id' or 'slug')
        result = list(seen_names.values())

        return result

    def get_user_list(self):
        return self.remove_duplicates(list(self.RESULT_QUERY.queue))