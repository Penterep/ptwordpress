import requests
from ptlibs import ptprinthelper
import http.client

class SourceEnumeration:
    def __init__(self, rest_url, args, ptjsonlib):
        self.REST_URL = rest_url
        self.BASE_URL = rest_url.split("/wp-json")[0]
        self.args = args
        self.ptjsonlib = ptjsonlib

    def run(self):
        self.find_xmlrpc()

    def find_xmlrpc(self):
        response = requests.get(f"{self.BASE_URL}/xmlrpc.php", proxies=self.args.proxy, verify=False)
        ptprinthelper.ptprint(f"{self.BASE_URL}/xmlrpc.php:", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)
        ptprinthelper.ptprint(f"[{response.status_code}] {http.client.responses.get(response.status_code, 'Unknown status code')}", "VULN" if response.status_code == 200 else "OK", condition=not self.args.json, indent=4)
