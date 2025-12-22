import tqdm
from time import sleep
from urllib.parse import urljoin
from ptlibs.http.http_client import HttpClient
from concurrent.futures import ThreadPoolExecutor, as_completed

class Guessing:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(self.args, self.ptjsonlib)


    def test_login_protection_and_weak_passwords(self, usernames, weak_passwords):
        self.login_url = f"{self.args.url.rstrip('/')}/wp-login.php"
        successful_logins = []
        for username in usernames:
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                futures = [executor.submit(self.attempt_login, username, pw) for pw in weak_passwords]

                for future in tqdm(as_completed(futures), total=len(futures), desc=f"Testing {username}", leave=False):
                    username, password, result = future.result()
                    if result == "success":
                        successful_logins.append((username, password))
                    if result == "blocked":
                        return successful_logins, "blocked"
        return successful_logins, "completed"

    def attempt_login(self,username, password):
        payload = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': f'{self.args.url.rstrip("/")}/wp-admin/',
            'testcookie': '1'
        }

        try:
            response = self.http_client.send_request(self.login_url, method="POST", data=payload)
        except Exception as e:
            return  (username, password, "blocked")

        cookie_header = response.headers.get('Set-Cookie', '')

        if 'wordpress_logged_in' in cookie_header:
            return (username, password, "success")

        if "captcha" in response.text.lower() or "blocked" in response.text.lower():
            return (username, password, "blocked")

        return (username, password, "fail")