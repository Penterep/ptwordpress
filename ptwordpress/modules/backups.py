import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from ptlibs import ptprinthelper
from queue import Queue

class BackupsFinder:
    def __init__(self, args, ptjsonlib, head_method_allowed):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.head_method_allowed = head_method_allowed
        self.vuln_urls = Queue()

    def run(self, domain):
        """Main function"""
        futures = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures.append(executor.submit(self.check_backup, domain))
            futures.append(executor.submit(self.check_files, domain))
            futures.append(executor.submit(self.check_wp_config, domain))
            futures.append(executor.submit(self.check_domain_files, domain))

         # Wait for tasks to finish
        for future in as_completed(futures):
            future.result()

        self.vuln_urls = set(list(self.vuln_urls.queue))
        if not self.vuln_urls:
            ptprinthelper.ptprint(f"None", "TEXT", condition=not self.args.json, indent=4, flush=True, clear_to_eol=True)
        else:
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.args.json, flush=True, clear_to_eol=True)

    def check_url(self, url):
        """Funkce pro ověření, zda soubor/adresář existuje"""
        try:
            ptprinthelper.ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url) if not self.head_method_allowed else requests.head(url)
            if response.status_code == 200:
                ptprinthelper.ptprint(f"{url}", "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                self.vuln_urls.put(url)
        except requests.exceptions.RequestException as e:
            pass

    def check_backup(self, domain):
        """Funkce pro kontrolu adresáře /backup"""
        url = f"http://{domain}/backup"
        self.check_url(url)

    def check_files(self, domain):
        """Funkce pro kontrolu souborů s různými koncovkami (backup, public, wordpress-backup, ...)"""
        extensions = ['sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj']
        files = ["backup", "public", "wordpress-backup", "database_backup", "public_html_backup"]

        for file in files:
            for ext in extensions:
                url = f"http://{domain}/{file}.{ext}"
                self.check_url(url)

    def check_wp_config(self, domain):
        """Funkce pro kontrolu souboru /wp-config.php s různými koncovkami"""
        extensions = ['sql', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj',
                    'php_', 'php~', 'bak', 'old', 'zal', 'backup', 'bck',
                    'php.bak', 'php.old', 'php.zal', 'php.bck', 'php.backup']
        url = f"http://{domain}/wp-config.php"
        for ext in extensions:
            self.check_url(f"{url}.{ext}")

    def check_domain_files(self, domain):
        """Funkce pro kontrolu souboru, který se jmenuje stejně jako doména"""
        extensions = ['sql', 'sql.gz', 'zip', 'rar', 'tar', 'tar.gz', 'tgz', '7z', 'arj']
        for ext in extensions:
            url = f"http://{domain}/{domain}.{ext}"
            self.check_url(url)

