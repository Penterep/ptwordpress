from ptlibs.ptprinthelper import ptprint
import requests
import time
import re

class HttpClient:
    _instance = None

    # The __new__ method ensures that only one instance of the class is created
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            # If no instance exists, create a new one
            cls._instance = super().__new__(cls)  # No need to pass *args or **kwargs
        return cls._instance

    def __init__(self, args=None, ptjsonlib=None):
        # This ensures __init__ is only called once
        if not hasattr(self, 'initialized'):
            if args is None or ptjsonlib is None:
                raise ValueError("Both 'args' and 'ptjsonlib' must be provided")

            self.args = args
            self.ptjsonlib = ptjsonlib
            self.proxy = self.args.proxy
            #input(self.proxy)
            self.delay = getattr(self.args, 'delay', 0)
            self.initialized = True  # Flag to indicate that initialization is complete

    def send_request(self, url, method="GET", *, headers=None, data=None, allow_redirects=True, **kwargs):
        """Wrapper for requests.request that allows dynamic passing of arguments."""
        try:
            response = requests.request(method=method, url=url, allow_redirects=allow_redirects, headers=headers, data=data, proxies=self.proxy if self.proxy else {}, verify=False if self.proxy else True)

            if method.upper() == "GET":
                self._check_fpd_in_response(response)

            if self.delay > 0:
                time.sleep(self.delay / 1000)  # Convert ms to seconds
            return response
        except Exception as e:
            # Re-raise the original exception with some additional context
            self.ptjsonlib.end_error(f"Error connecting to server: {e}", self.args.json)

    def is_valid_url(self, url):
        # A basic regex to validate the URL format
        regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    def _check_fpd_in_response(self, response, *, base_indent=4):
        """
        Checks the given HTTP response for Full Path Disclosure (FPD) errors.

        Args:
            response (requests.Response): The HTTP response to check for FPD errors.

        Prints:
            An error message if FPD is found in the response, otherwise indicates no FPD error.
        """
        error_patterns = [
            r"<b>Warning</b>: .* on line.*",
            r"<b>Fatal error</b>: .* on line.*",
            r"<b>Error</b>: .* on line.*",
            r"<b>Notice</b>: .* on line.*"
        ]
        try:
            # Check for FPD errors in the response
            for pattern in error_patterns:
                match = re.search(pattern, response.text)
                if match:
                    ptprint(f"[{response.status_code}] {response.url} contains FPD eror message: {match.group(0)}", "VULN", condition=not self.args.json, indent=base_indent)
                    return
            #print("No FPD error found in the response.")
        except Exception as e:
            print(f"Error during FPD check: {e}")