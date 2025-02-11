import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from ptlibs import ptprinthelper
from queue import Queue

import ptlibs.tldparser as tldparser

class BackupsFinder:
    def __init__(self, args, ptjsonlib, head_method_allowed):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.head_method_allowed = head_method_allowed
        self.vuln_urls = Queue()
        self.scheme =  None
        self.paths = ["/", "/wp-content/"]

    def run(self, base_url):
        """Main function"""
        extract_result = tldparser.extract(base_url)
        self.scheme =  extract_result.scheme
        domain = ((extract_result.subdomain + ".") if extract_result.subdomain else "") + extract_result.domain + "." + extract_result.suffix
        futures = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures.append(executor.submit(self.check_backup, domain))
            futures[0].result()  # This blocks until check_backup is finished, to add more potential paths to test
            #futures.append(executor.submit(self.check_files, domain))
            futures.append(executor.submit(self.check_wp_config, domain))
            futures.append(executor.submit(self.check_domain_files, domain))
            futures.append(executor.submit(self.check_log_files, domain))

         # Wait for tasks to finish
        for future in as_completed(futures):
            future.result()

        self.vuln_urls = set(list(self.vuln_urls.queue))
        if not self.vuln_urls:
            ptprinthelper.ptprint(f"No backup files discovered", "OK", condition=not self.args.json, indent=4, flush=True, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, flush=True, clear_to_eol=True, end="")

    def check_url(self, url):
        """Funkce pro ověření, zda soubor/adresář existuje"""
        try:
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False) if not self.head_method_allowed else requests.head(url, proxies=self.args.proxy, verify=False)
            if response.status_code == 200:
                ptprinthelper.ptprint(f"{url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                self.vuln_urls.put(url)
                return True
        except requests.exceptions.RequestException as e:
            print(e)
            pass
        return False

    def check_backup(self, domain):
        """Funkce pro kontrolu adresáře /backup"""
        for path in ["backup/", "backups/", "wp-content/backup/", "wp-content/backups/" ]:
            url = f"{self.scheme}://{domain}/{path}"
            if self.check_url(url):
                self.paths.append(path)

    def check_files(self, domain):
        """Funkce pro kontrolu souborů s různými koncovkami (backup, public, wordpress-backup, ...)"""
        extensions = ['', 'sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj']
        files = ["backup", "public", "wordpress-backup", "database_backup", "public_html_backup"]
        for path in self.paths:
            for file in files:
                for ext in extensions:
                    url = f"{self.scheme}://{domain}{path}{file}" + f".{ext}" if ext else ""
                    self.check_url(url)

    def check_wp_config(self, domain):
        """Funkce pro kontrolu souboru /wp-config.php s různými koncovkami"""
        extensions = ['sql', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj',
                    'php_', 'php~', 'bak', 'old', 'zal', 'backup', 'bck',
                    'php.bak', 'php.old', 'php.zal', 'php.bck', 'php.backup']
        url = f"{self.scheme}://{domain}/wp-config.php"
        for ext in extensions:
            self.check_url(f"{url}.{ext}")

    def check_domain_files(self, domain):
        """Funkce pro kontrolu souboru, který se jmenuje stejně jako doména"""
        extensions = ['sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj']
        for path in self.paths:
            for ext in extensions:
                url = f"{self.scheme}://{domain}{path}{domain}.{ext}"
                self.check_url(url)

    def check_log_files(self, domain):
        log_files = [
            "/wp-content/log/",
            "/wp-content/logs/",
            "/wp-content/debug.log",
            "/wp-content/access.log",
            "/wp-content/error.log",
            "/wp-content/log/debug.log",
            "/wp-content/log/access.log",
            "/wp-content/log/error.log",
            "/wp-content/logs/debug.log",
            "/wp-content/logs/access.log",
            "/wp-content/logs/error.log",
        ]

        for path in log_files:
            url = f"{self.scheme}://{domain}{path}"
            self.check_url(url)