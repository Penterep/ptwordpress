import requests
from ptlibs import ptprinthelper
import defusedxml.ElementTree as ET

class UserEnumeration:
    def __init__(self, rest_url, args, ptjsonlib):
        self.ptjsonlib = ptjsonlib
        self.args = args
        self.REST_URL = rest_url
        self.BASE_URL = rest_url.split("/wp-json")[0]
        self.FOUND_AUTHOR_IDS = set()
        self.ENUMERATED_USERS = []
        self.vulnerable_endpoints: set = set() # List of URL spots allowing user enumeration

    def print_vulnerable_endpoints(self):
        ptprinthelper.ptprint(f"Vulnerable endpoints (allowing user enumeration):", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        self.vulnerable_endpoints =  {u[:-1] if u.endswith("/") else u for u in [u.split("?")[0] for u in self.vulnerable_endpoints]}
        for url in self.vulnerable_endpoints:
                ptprinthelper.ptprint(url, "TEXT", condition=not self.args.json, indent=4)

    def enumerate_users(self):
        ptprinthelper.ptprint(f"User enumeration:", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        self._enumerate_wp_v2_users()
        self._enumerate_wp_v2_users_via_paginator()
        self._enumerate_users_via_posts()
        #self._enumerate_wp_v2_users_via_posts(url=f"{self.REST_URL}/wp/v2/users/?per_page=100&page=1")
        #self._enumerate_users_by_author_query(url=f"{self.REST_URL}/?author=",)
        self.map_user_id_to_slug()
        self._scrape_feed()
        self.print_vulnerable_endpoints()

    def _enumerate_wp_v2_users(self) -> list:
        response = requests.get(f"{self.REST_URL}/wp/v2/users")
        if response.status_code == 200:
            for user_dict in response.json():
                self.FOUND_AUTHOR_IDS.add(user_dict.get("id"))
                self.vulnerable_endpoints.add(response.url)

    def _enumerate_wp_v2_users_via_paginator(self) -> list:
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/users/?per_page=100&page={i}")
            if response.status_code == 200:
                if not response.json():
                    break
                for post in response.json():
                    author_id, author_name, author_slug = post.get("id"), post.get("name"), post.get("slug")
                    if author_id:
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(response.url)
            if response.status_code != 200:
                break

    def _enumerate_users_via_posts(self):
        """Enumerate user ids via https://example.com/wp-json/wp/v2/posts/?per_page=100&page=1"""
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/posts/?per_page=100&page={i}", allow_redirects=True)
            if response.status_code == 200:
                if not response.json():
                    break
                for post in response.json():
                    author_id = post.get("author")
                    if author_id:
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(response.url)
            if response.status_code != 200:
                break

    def _enumerate_users_by_author_query(self, url: str, end = None) -> list:
        for i in range(100):
            response = requests.get(f"{self.BASE_URL}/?author={i}", allow_redirects=True)
            if response.status_code == 200:
                # If 200 and does not translate to username, means no posts by author. still can be retrieved from response (depending on theme possibly)
                pass

    def _enumerate_users_via_comments(self):
        for i in range(1, 100):
            response = requests.get(f"{self.REST_URL}/wp/v2/comments/?per_page=100&page={i}", allow_redirects=True)
            if response.status_code == 200:
                if not response.json():
                    break
                for comment in response.json():
                    author_id, author_name, author_slug = comment.get("author"), comment.get("author"), comment.get("author")
                    if author_id:
                        print(author_id)
                        self.FOUND_AUTHOR_IDS.add(author_id)
                        self.vulnerable_endpoints.add(response.url)
            if response.status_code != 200:
                break

    def map_user_id_to_slug(self):
        for i in sorted(list(self.FOUND_AUTHOR_IDS)):
            response = requests.get(f"{self.REST_URL}/wp/v2/users/{i}", allow_redirects=True)
            if response.status_code == 200:
                slug = response.json().get("slug")
                self.ENUMERATED_USERS.append({"id": i, "slug": slug})
                ptprinthelper.ptprint(f"{i}: {slug}", "TEXT", condition=not self.args.json, indent=4)
            if response.status_code != 200:
                break

    def _scrape_feed(self):
        """User enumeration via RSS feed"""
        ptprinthelper.ptprint(f"RSS feed users:", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        rss_authors = set()
        response = requests.get(f"{self.BASE_URL}/feed")
        if response.status_code == 200:
            root = ET.fromstring(response.text.strip())
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
            ptprinthelper.ptprint(f"Feed not found", "TEXT", condition=not self.args.json, indent=4)