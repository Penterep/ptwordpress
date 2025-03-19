"""Helpers"""
import requests

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
            self.initialized = True  # Flag to indicate that initialization is complete

    def send_request(self, url, method="GET", *, headers=None, data=None, allow_redirects=True, **kwargs):
        """Wrapper for requests.request that allows dynamic passing of arguments."""
        try:
            response = requests.request(method=method, url=url, allow_redirects=allow_redirects, headers=headers, data=data, proxies=self.proxy, verify=not bool(self.proxy))
            return response
        except Exception as e:
            # Re-raise the original exception with some additional context
            raise requests.RequestException(f"Request failed: {e}") from e
            raise #requests.RequestException(f"Request failed: {e}") from e
            #return None

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


    def load_url(url: str, method: str, **kwargs) -> requests.Response:
        """
        A simplified version that delegates to the full function with fewer arguments.
        """
        return load_url_from_web_or_temp(url, method, **kwargs)

    def load_url_from_web_or_temp(url: str, method: str, headers: dict = {}, proxies: dict = {}, data: dict = None, timeout: int = None, redirects: bool = False, verify: bool = False, cache: bool = False, dump_response: bool = False, auth: tuple[str, str] = None) -> requests.Response:
        """Returns HTTP response from URL.
        If param <cache_request> is present, response will be saved into a temp file. If response is already saved in a temp file, it will be loaded from there.

        Args:
            url            (str)  : request url
            method         (str)  : request method
            headers        (dict) : request headers
            proxies        (dict) : request proxies
            data           (dict) : request post data
            timeout        (int)  : request timeout
            redirects      (bool) : follow redirects
            verify         (bool) : verify requests
            cache          (bool) : cache request-response
            dump_response  (bool) : dump request-response
            auth           (tuple[str, str]) : use HTTP authentication

        Returns:
            default:
                requests.models.Response: response
            with dump_response:
                tuple: ( response: requests.Response, request_dump: dict )
        """
        if cache:
            # Create penterep dir in tmp if not present
            if not os.path.exists(os.path.join(tempfile.gettempdir(), "pentereptools")):
                os.makedirs(os.path.join(tempfile.gettempdir(), "pentereptools"))

            filename = get_temp_filename_from_url(url, method, headers)
            if exists_temp(filename):
                obj = load_object(filename)
                return obj["response"] if not dump_response else (obj["response"], obj["response_dump"])
            else:
                response = _get_response(url, method, headers, proxies, data, timeout, redirects, verify, auth)
                response_dump = get_response_data_dump(response)
                save_object({"response": response, "response_dump": response_dump}, filename)
                return response if not dump_response else (response, response_dump)
        else:
            response = _get_response(url, method, headers, proxies, data, timeout, redirects, verify, auth)
            return response if not dump_response else (response, get_response_data_dump(response))