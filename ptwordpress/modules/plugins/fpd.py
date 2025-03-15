"""FPD tests"""
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from ptlibs.ptprinthelper import ptprint
import ptlibs.tldparser as tldparser


class FullPathDisclosure:
    def __init__(self, args, base_url):
        self.args = args
        self.base_url = base_url
        self.full_domain = self._get_full_domain()

    def check_full_path_disclosure(self):
        """Check for Full Path Disclosure"""
        ptprint(f"Search for Full Path Disclosure", "TITLE", condition=not self.args.json, newline_above=True, indent=0, colortext=True)
        paths = [
            "/wp-includes/compat.php",
            "/wp-includes/meta.php",
            "/wp-content/plugins/hello.php",
            "/wp-content/plugins/wordpress-seo/admin/admin-settings-changed-listener.php",
            "/wp-content/db.php",
        ]
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            result = list(r for r in executor.map(self._check_url, paths) if isinstance(r, dict))
        if result:
            for result_dict in result:
                for vuln_path, leaked_paths in result_dict.items():
                    ptprint(f'\n    '.join(leaked_paths), "VULN", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)
                    ptprint(self.base_url + vuln_path, "ADDITIONS", condition=not self.args.json, end="\n", flush=True, indent=8, clear_to_eol=True)
        else:
            ptprint("No Full Path Disclosure discovered", "OK", condition=not self.args.json, end="\n", flush=True, indent=4, clear_to_eol=True)

    def _check_url(self, path):
        """Thread function"""
        try:
            url = self.full_domain + "/" + path
            ptprint(f"{url}", "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
            response = requests.get(url, proxies=self.args.proxy, verify=False, allow_redirects=False, headers=self.args.headers)
            pattern = r"(?:in\s+)([a-zA-Z]:\\[\\\w.-]+|/[\w./-]+)"
            matches: list = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                return {path: matches}
        except:
            return

    def _get_full_domain(self):
        """Build full domain"""
        extract_result = tldparser.extract(self.base_url)
        domain = ((extract_result.subdomain + ".") if extract_result.subdomain else "") + extract_result.domain + "." + extract_result.suffix
        scheme = extract_result.scheme
        full_domain = f"{scheme}://{domain}"
        return full_domain
