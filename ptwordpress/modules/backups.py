import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from ptlibs import ptprinthelper
from queue import Queue
import http.client
import ptlibs.tldparser as tldparser
import os

class BackupsFinder:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed):
        self.vulnerable_urls = Queue()
        self.head_method_allowed = head_method_allowed
        self.ptjsonlib = ptjsonlib
        self.args = args
        #self.paths = ["/", "/wp-content/"]
        self.extract_result = tldparser.extract(base_url)
        self.base_domain = self.extract_result.domain + "." + self.extract_result.suffix
        self.domain      = ((self.extract_result.subdomain + ".") if self.extract_result.subdomain else "") + self.extract_result.domain + "." + self.extract_result.suffix
        self.scheme      = self.extract_result.scheme
        self.full_domain = f"{self.scheme}://{self.domain}"

    def run_backup_discovery(self) -> list:
        """Main function, returns set of vulnerable urls."""
        self.vulnerable_urls = Queue()
        ptprinthelper.ptprint(f"Backups discovery", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        domain = ((self.extract_result.subdomain + ".") if self.extract_result.subdomain else "") + self.extract_result.domain + "." + self.extract_result.suffix
        base_domain = self.extract_result.domain + "." + self.extract_result.suffix

        self.check_backup(domain)
        self.check_specific_files(domain)
        self.check_wp_config(domain)
        self.check_domain_files(base_domain)

        self.vulnerable_urls = set(list(self.vulnerable_urls.queue))
        if not self.vulnerable_urls:
            ptprinthelper.ptprint(f"No backup files discovered", "OK", condition=not self.args.json, indent=4, flush=True, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, flush=True, clear_to_eol=True, end="")

        return list(self.vulnerable_urls)

    def run_log_discovery(self):
        self.vulnerable_urls = Queue()
        ptprinthelper.ptprint(f"Logs discovery", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        domain = ((self.extract_result.subdomain + ".") if self.extract_result.subdomain else "") + self.extract_result.domain + "." + self.extract_result.suffix
        self.check_log_files(domain)

        self.vulnerable_urls = set(list(self.vulnerable_urls.queue))
        if not self.vulnerable_urls:
            ptprinthelper.ptprint(f"No log files discovered", "OK", condition=not self.args.json, indent=4, flush=True, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, flush=True, clear_to_eol=True, end="")

    def discover_database_management_interface(self):
        files = [
            "/adminer/adminer.php",
            "/adminer.php",
            "/admin/adminer.php",
            "/wp-admin/adminer.php",
            "/phpmyadmin/",
            "/admin/phpmyadmin/",
            "/wp-admin/phpmyadmin/",
            "/database/",
            "/cpanel/",]

        self.vulnerable_urls = Queue()
        domain = ((self.extract_result.subdomain + ".") if self.extract_result.subdomain else "") + self.extract_result.domain + "." + self.extract_result.suffix
        ptprinthelper.ptprint(f"Database management interface", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.check_url, self.scheme + "://" + domain + file_) for file_ in files]

        self.vulnerable_urls = set(list(self.vulnerable_urls.queue))
        if not self.vulnerable_urls:
            ptprinthelper.ptprint(f"No database management interface discovered", "OK", condition=not self.args.json, indent=4, flush=True, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, flush=True, clear_to_eol=True, end="")

    def check_url(self, url):
        """Funkce pro ověření, zda soubor/adresář existuje"""
        try:
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False) if not self.head_method_allowed else requests.head(url, proxies=self.args.proxy, verify=False, allow_redirects=False)
            if response.status_code == 200:
                ptprinthelper.ptprint(f"[{response.status_code}] {http.client.responses.get(response.status_code, '')} {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                self.vulnerable_urls.put(url)
                return True
        except requests.exceptions.RequestException as e:
            pass
        return False

    def check_backup(self, domain):
        """Funkce pro kontrolu adresáře /backup"""
        #for path in ["backup/", "backups", "wp-content/backup", "wp-content/backups"]:
        path_to_wordlist = os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "wordlists", "backups.txt")

        with open(path_to_wordlist, "r") as file:
            paths = (path.strip() for path in file.readlines())  # Generátor pro slova

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for path in paths:
                    url = f"{self.scheme}://{self.domain}{path}"
                    futures.append(executor.submit(self.check_url, url))
                for future in as_completed(futures):
                    future.result()

    def check_specific_files(self, domain):
        """Funkce pro kontrolu souborů s různými koncovkami (backup, public, wordpress-backup, ...)"""
        extensions = ['', 'sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj']
        files = ["backup", "public", "wordpress-backup", "database_backup", "public_html_backup"]

        with ThreadPoolExecutor() as executor:
            # Spuštění všech kontrol pro různé kombinace souborů a přípon
            executor.map(lambda file: [self.check_url(f"{self.scheme}://{self.domain}{path}{file}{f'.{ext}' if ext else ''}") for path in ["/", "/wp-content/"] for ext in extensions] , files)

    def check_wp_config(self, domain):
        """Funkce pro kontrolu souboru /wp-config.php s různými koncovkami"""
        extensions = ['sql', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj',
                    'php_', 'php~', 'bak', 'old', 'zal', 'backup', 'bck',
                    'php.bak', 'php.old', 'php.zal', 'php.bck', 'php.backup']
        url = f"{self.scheme}://{self.domain}/wp-config"
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(lambda ext: self.check_url(f"{url}.{ext}"), extensions) # Spuštění všech kontrol pro různé přípony

    def check_domain_files(self, domain_name):
        """Funkce pro kontrolu souboru, který se jmenuje stejně jako doména"""
        extensions = ['sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj']
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Spuštění všech kontrol pro různé přípony
            executor.map(lambda ext: [self.check_url(f"{self.scheme}://{self.domain}{path}{domain_name}.{ext}") for path in ["/", "/wp-content/"]], extensions)

    def check_log_files(self, domain):
        path_to_wordlist = os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "wordlists", "logs.txt")
        with open(path_to_wordlist, "r") as file:
            paths = (path.strip() for path in file.readlines())  # Generátor pro slova

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for path in paths:
                    url = f"{self.scheme}://{self.domain}{path}"
                    futures.append(executor.submit(self.check_url, url))
                for future in as_completed(futures):
                    future.result()

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
            result = executor.map((self.check_url, urls))

    def check_url(self, url):
        """Funkce pro ověření, zda soubor/adresář existuje"""
        try:
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False) if not self.head_method_allowed else requests.head(url, proxies=self.args.proxy, verify=False, allow_redirects=False)
            if response.status_code == 200:
                ptprinthelper.ptprint(f"[{response.status_code}] {http.client.responses.get(response.status_code, '')} {url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                self.vulnerable_urls.put(url)
                return True
        except requests.exceptions.RequestException as e:
            pass
        return False