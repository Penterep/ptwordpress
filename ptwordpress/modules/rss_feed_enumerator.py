import hashlib
import requests
import http.client

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import defusedxml.ElementTree as ET

from ptlibs import ptprinthelper


class RssFeedEnumerator:
    def __init__(self, base_url, args):
        """
        Initialize the object for user enumeration via RSS feed.

        :param base_url: Base URL for the RSS feed.
        :param args: Arguments containing proxy and author range.
        """
        self.BASE_URL = base_url
        self.proxy = args.proxy
        self.author_range = args.author_range
        self.args = args

        # Sets for tracking unique responses and redirects
        self.seen_hashes = set()
        self.seen_redirects = set()

        # Locks for safe access across threads
        self.hash_lock = Lock()
        self.redirect_lock = Lock()

        # Flag to stop loops
        self.stop_flag = False

    def run(self):
        """Main function for user enumeration via RSS feed"""
        ptprinthelper.ptprint(f"User enumeration via RSS feed", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        for path in ["/feed/", "/feed/rss", "/?feed=rss&author=1", "/feed/rss?author=1", "/feed/rss?paged=1"]:
            url = self.BASE_URL + path  # example.com/feed/rss
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\n", flush=True, colortext=True, indent=4, clear_to_eol=True)

            try:
                response = requests.get(url=url, proxies=self.proxy, verify=False, allow_redirects=False)
                response_hash = hashlib.md5(response.content).hexdigest()
                ptprinthelper.ptprint(f"[{response.status_code} {http.client.responses.get(response.status_code, '')}] {response.headers.get('location', '')} {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

                # If the response is 200, add the hash to the set and send more requests
                if response.status_code == 200:
                    self.seen_hashes.add(response_hash)

                    if path.endswith("=1"):  # If the first response is 200, send more requests
                        batch_size = 5
                        author_id = self.author_range[0]

                        while not self.stop_flag and author_id < self.author_range[1]:
                            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                                results = list(executor.map(lambda i: self.send_request_and_parse(path, i), range(author_id, author_id + batch_size)))

                                # If we receive None, stop the loop
                                for result in results:
                                    if result:
                                        print(result)

                            if any(result is None for result in results):  
                                break

                            author_id += batch_size

                # Handling redirection if it occurs
                elif response.is_redirect:
                    input((url, "url je redirekt")) 
                    self.handle_redirect(response, path)

            except requests.RequestException as e:
                pass

    def send_request_and_parse(self, path, i):
        """Send a request and parse the response"""
        url = self.BASE_URL + path.replace("=1", f"={i}")
        final_url = self.handle_redirect(url)  # Follow redirect if needed
        try:
            response = requests.get(final_url, allow_redirects=False, proxies=self.proxy, verify=False)

            if response.status_code == 200:
                response_hash = hashlib.md5(response.content).hexdigest()
                if response_hash in self.seen_hashes:
                    return None

                with self.hash_lock:
                    if response_hash in self.seen_hashes:
                        return None  # Duplicate, exit

                    self.seen_hashes.add(response_hash)
                return self.parse_feed(response)  # Call function to process data

            elif response.is_redirect:
                # If redirect, check if URL contains "feed" or "rss"
                redirect_url = response.headers.get('Location')
                if redirect_url and ('feed' in redirect_url or 'rss' in redirect_url):
                    with self.redirect_lock:
                        if redirect_url in self.seen_redirects:
                            return None  # If we've already visited this URL, exit
                        self.seen_redirects.add(redirect_url)  # Add redirect URL to tracking
                    return self.send_request_and_parse(path, i)  # Recursively continue with the redirect

        except requests.RequestException:
            pass

    def handle_redirect(self, response, path=None):
        """Handles redirects by checking if the URL is redirected to a valid feed"""
        try:
            if response.is_redirect:
                redirect_url = response.headers.get('Location')
                if redirect_url and ('feed' in redirect_url or 'rss' in redirect_url):
                    with self.redirect_lock:
                        if redirect_url in self.seen_redirects:
                            return None  # If we've already visited this URL, exit
                        self.seen_redirects.add(redirect_url)  # Add redirect URL to tracking
                    return redirect_url  # Return the redirect URL to follow
            return response.url if path is None else self.BASE_URL + path
        except requests.RequestException:
            return response.url if path is None else self.BASE_URL + path

    def parse_feed(self, response):
        """Parse users out of feed"""
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
