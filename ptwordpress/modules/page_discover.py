import csv
import concurrent.futures

from ptlibs import ptprinthelper
from ptlibs.http.http_client import HttpClient

from modules.helpers import print_api_is_not_available


class PageDiscover:
    def __init__(self, base_url, args, ptjsonlib):
        self.args = args
        self.BASE_URL = base_url
        self.REST_URL = base_url + "/wp-json"
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(self.args, self.ptjsonlib)

    def _parse_page(self, page):
        return {
            "id": page.get("id"),
            "date": page.get("date"),
            "date_gmt": page.get("date_gmt"),
            "guid": page.get("guid", {}).get("rendered"),
            "modified": page.get("modified"),
            "modified_gmt": page.get("modified_gmt"),
            "slug": page.get("slug"),
            "status": page.get("status"),
            "type": page.get("type"),
            "link": page.get("link"),
            "title": page.get("title", {}).get("rendered"),
            "author_id": page.get("author"),
            "parent": page.get("parent"),
            "menu_order": page.get("menu_order"),
            "template": page.get("template"),
        }

    def _get_author(self, author_id, users_table):
        """Map a WordPress author ID to known slug/name data."""
        author = {"id": author_id, "nickname": "", "name": ""}

        users = users_table.get_users() if hasattr(users_table, "get_users") else users_table
        for user in users:
            if str(user.get("id")) == str(author_id):
                author["nickname"] = user.get("slug") or ""
                author["name"] = user.get("name") or ""
                break
        return author

    def _deduplicate_pages_by_link(self, pages):
        """Return pages without duplicate links while preserving discovery order."""
        result = []
        seen_links = set()

        for page in pages:
            link = page.get("link")
            if link in seen_links:
                continue

            seen_links.add(link)
            result.append(page)

        return result

    def print_pages(self, users_table):
        """Print all pages discovered via WordPress REST API."""
        def fetch_page(page_number):
            try:
                url = f"{self.REST_URL}/wp/v2/pages?page={page_number}&per_page=100"
                ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
                response = self.http_client.send_request(url, method="GET")
                if response.status_code == 200 and response.json():
                    return [self._parse_page(page) for page in response.json()]
            except Exception:
                return

        result = []
        ptprinthelper.ptprint(f"Discovered pages {'(link, id, author id, author nickname, author name, date, title)' if self.args.verbose else ('links')}", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        response = None
        try:
            response = self.http_client.send_request(f"{self.REST_URL}/wp/v2/pages?page=1&per_page=100", method="GET", allow_redirects=False)
            if response.status_code != 200:
                raise ValueError
            result.extend([self._parse_page(page) for page in response.json()])
        except Exception:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            page_range = range(2, 100)
            for i in range(0, len(page_range), 10):
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

        result = self._deduplicate_pages_by_link(result)

        for page in result:
            ptprinthelper.ptprint(page.get("link"), "TEXT", colortext=False, condition=not self.args.json, indent=4, clear_to_eol=True)
            if self.args.verbose:
                author = self._get_author(page.get("author_id"), users_table)
                ptprinthelper.ptprint(f'{page.get("id")}, {author.get("id")}, {author.get("nickname")}, {author.get("name")}, {page.get("date")}, {page.get("title")}', "ADDITIONS", colortext=True, condition=not self.args.json, indent=4, clear_to_eol=True)

        if not result:
            ptprinthelper.ptprint(f"No pages discovered", "OK", condition=not self.args.json, indent=4, clear_to_eol=True)

        if self.args.output:
            self.save_pages_as_csv(result, users_table)

        return result

    def save_pages_as_csv(self, pages: list, users_table):
        """Save discovered pages with mapped author metadata to CSV."""
        csv_filename = f"{self.args.output}-pages.csv"
        with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["LINK", "ID", "AUTHOR_ID", "AUTHOR_NICKNAME", "AUTHOR_NAME", "DATE", "DATE_GMT", "MODIFIED", "MODIFIED_GMT", "SLUG", "STATUS", "TYPE", "TITLE", "PARENT", "MENU_ORDER", "TEMPLATE"])

            for page in pages:
                author = self._get_author(page.get("author_id"), users_table)
                writer.writerow([
                    page.get("link"),
                    page.get("id"),
                    author.get("id"),
                    author.get("nickname"),
                    author.get("name"),
                    page.get("date"),
                    page.get("date_gmt"),
                    page.get("modified"),
                    page.get("modified_gmt"),
                    page.get("slug"),
                    page.get("status"),
                    page.get("type"),
                    page.get("title"),
                    page.get("parent"),
                    page.get("menu_order"),
                    page.get("template"),
                ])
