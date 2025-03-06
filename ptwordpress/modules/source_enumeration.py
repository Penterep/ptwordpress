import requests
import http.client
from ptlibs import ptprinthelper
from ptlibs.ptprinthelper import ptprint
from queue import Queue
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import ptlibs.tldparser as tldparser

from modules.backups import BackupsFinder
from modules.write_to_file import write_to_file

class SourceEnumeration:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed: bool):
        self.BASE_URL = base_url
        self.REST_URL = base_url + "/wp-json"
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.head_method_allowed = head_method_allowed

        self.extract_result = tldparser.extract(base_url)
        #self.base_domain = self.extract_result.domain + "." + self.extract_result.suffix
        self.domain      = ((self.extract_result.subdomain + ".") if self.extract_result.subdomain else "") + self.extract_result.domain + "." + self.extract_result.suffix
        self.scheme      = self.extract_result.scheme
        self.full_domain = f"{self.scheme}://{self.domain}"

    def print_media(self, enumerated_users):
        """Print all media discovered via API"""

        def get_user_slug_or_name(user_id):
            for user in enumerated_users:
                if user["id"] == str(user_id):
                    return user.get("slug") or user.get("name")
            return str(user_id)

        def fetch_page(page):
            """Stáhne jednu stránku z API"""
            try:
                scrapped_media = []
                url = f"{self.BASE_URL}/wp-json/wp/v2/media?page={page}&per_page=100"
                ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
                response = requests.get(url, proxies=self.args.proxy, verify=False)
                if response.status_code == 200 and response.json():
                    for m in response.json():
                        scrapped_media.append({"source_url": m.get("source_url"), "author_id": m.get("author"), "uploaded": m.get("date_gmt"), "modified": m.get("modified_gmt"), "title": m["title"].get("rendered")})
                    return scrapped_media
            except Exception as e:
                return


        result = []
        source_urls = set()

        # Try get & parse Page 1
        ptprinthelper.ptprint(f"Media discovery (title, author, uploaded, modified, url)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        try:
            response = requests.get(f"{self.BASE_URL}/wp-json/wp/v2/media?page=1&per_page=100", proxies=self.args.proxy, verify=False)
            data = response.json()
            for m in response.json():
                result.append({"source_url": m.get("source_url"), "author_id": m.get("author"), "uploaded": m.get("date_gmt"), "modified": m.get("modified_gmt"), "title": m["title"].get("rendered")})
            if response.status_code != 200:
                raise ValueError
        except Exception as e:
            ptprinthelper.ptprint(f"API is not available [{response.status_code}]", "WARNING", condition=not self.args.json, indent=4)
            return


        #article_result = set()

        # Try get a parse Page 2-99
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            page_range = range(2, 100)  # Počínaje stránkou 2 až do 99
            for i in range(0, len(page_range), 10):  # Posíláme po 10 stránkách najednou
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

        #for source in source_urls:
        #    ptprinthelper.ptprint(source, "ADDITIONS", colortext=True, condition=not self.args.json, indent=4)
        for media in result:
            ptprinthelper.ptprint(f'{media.get("title")}, {get_user_slug_or_name(media.get("author_id"))}, {media.get("uploaded")}, {media.get("modified")}', "ADDITIONS", colortext=False, condition=not self.args.json, indent=4)
            ptprinthelper.ptprint(media.get("source_url"), "ADDITIONS", colortext=True, condition=not self.args.json, indent=4)

        if self.args.output:
            filename = self.args.output + "-media.txt"
            #if "." in self.args.output:
            #    splitted = self.args.output.split(".")
            #    filename = f"{splitted[0]}-media.{splitted[-1]}"
            write_to_file(filename, '\n'.join(source_urls))

        return source_urls

    def discover_xml_rpc(self):
        """Discover XML-RPC API"""
        xml_data = '''<?xml version="1.0" encoding="UTF-8"?>
        <methodCall>
          <methodName>system.listMethods</methodName>
          <params></params>
        </methodCall>'''
        ptprinthelper.ptprint(f"Testing for xmlrpc.php availability", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        response = requests.post(f"{self.BASE_URL}/xmlrpc.php", proxies=self.args.proxy, verify=False, data=xml_data, allow_redirects=False)
        ptprinthelper.ptprint(f"[{response.status_code}] {response.url}", "TEXT", condition=not self.args.json, indent=4)
        ptprinthelper.ptprint(f"Script xmlrpc.php is {'available' if response.status_code == 200 else 'not available'}", "VULN" if response.status_code == 200 else "OK", condition=not self.args.json, indent=4)

        #ptprinthelper.ptprint(f"[{response.status_code}] {http.client.responses.get(response.status_code, 'Unknown status code')} {'Available' if response.status_code == 200 else ''}", "VULN" if response.status_code == 200 else "OK", condition=not self.args.json, indent=4) 

    def discover_repositories(self):
        """Discover repositories by accessing ./git/HEAD, /.svn/entries files."""
        ptprinthelper.ptprint(f"Repository discovery", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        is_vuln = False
        for path in ["/.git/HEAD", "/wp-content/.git/HEAD", "/wp-content/uploads/.git/HEAD", "/.svn/entries", "/wp-content/.svn/entries", "/wp-content/uploads/.svn/entries" ]:
            url = self.BASE_URL + path
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url=url, proxies=self.args.proxy, verify=False, allow_redirects=False)
            try:
                if response.status_code == 200:
                    ptprinthelper.ptprint(f"Repository discovered: {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                    is_vuln = True
            except requests.RequestException as e:
                pass
        if not is_vuln:
            ptprinthelper.ptprint(f"No repository discovered", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

    def discover_config_files(self):
        """Discover .htaccess, .htpasswd config files"""
        ptprinthelper.ptprint(f"Check accesss to config files (.htaccess, .htpasswd)", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        is_vuln = False
        for path in ["/.htaccess", "/.htpasswd"]:
            url = self.BASE_URL + path
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url=url, proxies=self.args.proxy, verify=False, allow_redirects=False)
            try:
                if response.status_code == 200:
                    ptprinthelper.ptprint(f"Allowed access to config file: {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                    is_vuln = True
            except requests.RequestException as e:
                pass
        if not is_vuln:
            ptprinthelper.ptprint(f"Access to config files not allowed", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

    def discover_admin_login_page(self):
        """Discover admin page"""
        ptprint(f"Admin login page", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        result = [] # status code, url, redirect
        for path in  ["/wp-admin/", "/admin", "/wp-login.php"]:
            full_url = self.BASE_URL + path
            try:
                response = requests.get(full_url, allow_redirects=False, proxies=self.args.proxy, verify=False)
                # {http.client.responses.get(response.status_code, 'Unknown status code')}
                result.append([f"{response.status_code}" , f"{full_url}", response.headers.get("location", "")])
            except requests.exceptions.RequestException:
                result.append([f"[error]", f"{full_url}"])

        is_available = False # True if status code 200 anywhere
        # Print results
        max_url_length = max(len(url_from) for _, url_from, _ in result)
        for code, url_from, url_to in result:
            ptprint(f"[{code}] {url_from:<{max_url_length}} {'→ ' + url_to if url_to else ''}", "TEXT", condition=not self.args.json, indent=4)
            if str(code).startswith("2"):
                is_available = True

        ptprint("Admin page is available" if is_available else "Admin page is not available", "VULN" if is_available else "OK", condition=not self.args.json, indent=4)

    def check_directory_listing(self, url_list: list, print_text: bool = True) -> list:
        """Checks for directory listing, returns list of vulnerable URLs."""
        ptprint(f"Directory listing", "TITLE", condition=print_text and not self.args.json, newline_above=True, indent=0, colortext=True)
        vuln_urls = Queue()

        def check_url(url):
            """Funkce pro ověření jednoho URL"""
            if not url.endswith("/"): url += "/"
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=print_text and not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            try:
                response = requests.get(url, timeout=5, proxies=self.args.proxy, verify=False)
                if response.status_code == 200 and "index of /" in response.text.lower():
                    vuln_urls.put(url)  # ✅ Thread-safe zápis
                    ptprinthelper.ptprint(f"{url}", "VULN", condition=print_text and not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                else:
                    ptprinthelper.ptprint(f"{url}", "OK", condition=print_text and not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
            except requests.exceptions.RequestException as e:
                ptprint(f"Error retrieving response from {url}. Reason: {e}", "ERROR", condition=not self.args.json, indent=4)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_url, url_list)

        return list(vuln_urls.queue)

    def discover_logs(self):
        return BackupsFinder(base_url=self.BASE_URL, args=self.args, ptjsonlib=self.ptjsonlib, head_method_allowed=self.head_method_allowed).run_log_discovery()

    def discover_backups(self):
        """Run BackupFinder moduel to discover backups on target server"""
        return BackupsFinder(base_url=self.BASE_URL, args=self.args, ptjsonlib=self.ptjsonlib, head_method_allowed=self.head_method_allowed).run_backup_discovery()

    def discover_database_management_interface(self):
        return BackupsFinder(base_url=self.BASE_URL, args=self.args, ptjsonlib=self.ptjsonlib, head_method_allowed=self.head_method_allowed).discover_database_management_interface()


    def check_readme_files(self, themes, plugins):
        """"""
        ptprint(f"Check readme files", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        #ptprint(f"Readme discovery: {url}", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True, clear_to_eol=True)

        result = [self.check_url(url=f"{self.BASE_URL}/readme.html")]

        urls = []
        for t in themes:
            urls.append(f"{self.BASE_URL}/wp-content/themes/{t}/readme.txt")
        for p in plugins:
            urls.append(f"{self.BASE_URL}/wp-content/plugins/{p}/readme.txt")

        #return
        with ThreadPoolExecutor(max_workers=10) as executor:
            result.extend(list(executor.map(self.check_url, urls)))
        #input(result)

        if all(r is None for r in result):
            ptprinthelper.ptprint(f"No readme files enumerated", "OK", condition=not self.args.json, end="\n", flush=True, colortext=True, indent=4, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

        return result

    def check_dangerous_scripts(self):
        """"""
        ptprint(f"Check dangerous scripts", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        paths = [
            "/wp-mail.php",
            "/wp-cron.php",
            "/wp-signup.php",
            "/wp-activate.php",
            "/wp-admin/maint/repair.php",
        ]
        urls = [self.scheme + "://"+ self.domain + path for path in paths]
        with ThreadPoolExecutor(max_workers=10) as executor:
            result = list(executor.map(self.check_url, urls, [True] * len(urls)))

        #if all(r is None for r in result):
        #    ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\n", flush=True, colortext=True, indent=4, clear_to_eol=True)

    def check_url(self, url, show_responses=False):
        """Funkce pro ověření, zda soubor/adresář existuje"""
        try:
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False) if not self.head_method_allowed else requests.head(url, proxies=self.args.proxy, verify=False, allow_redirects=False)
            if response.status_code == 200:
                ptprinthelper.ptprint(f"[{response.status_code} {http.client.responses.get(response.status_code, '')}] {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                return url
            else:
                if show_responses:
                    ptprinthelper.ptprint(f"[{response.status_code} {http.client.responses.get(response.status_code, '')}] {url}", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

        except requests.exceptions.RequestException as e:
            return

    def check_settings_availability(self):
        ptprint(f"Check access to API", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        self.check_url(f"{self.full_domain}/wp-json/wp/v2/settings", show_responses=True),
        self.check_url(f"{self.full_domain}/wp-json/wp-site-health/v1/tests/background-updates", show_responses=True)

    def discover_phpinfo(self):
        ptprint(f"phpinfo()", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        paths = [
            "phpinfo.php",
            "phpinfo.php3",
            "info.php",
            "info.php3",
        ]
        urls = [self.scheme + "://"+ self.domain + "/" + path for path in paths]
        with ThreadPoolExecutor(max_workers=10) as executor:
            result = list(executor.map(self.check_url, urls, [False] * len(urls)))

        if all(r is None for r in result):
            ptprinthelper.ptprint(f"No files enumerated", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)


    def discover_status_files(self):
        ptprint(f"Searching for statistics", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        paths = [
            "/server-status",
            "/server-info",
            "/stats",
            "/stat",
            "/awstat",
            "/statistics",
        ]
        urls = [self.scheme + "://"+ self.domain + "/" + path for path in paths]
        with ThreadPoolExecutor(max_workers=10) as executor:
            result = list(executor.map(self.check_url, urls, [False] * len(urls)))

        if all(r is None for r in result):
            ptprinthelper.ptprint(f"No statistics discovered", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)