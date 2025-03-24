import requests
import time

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