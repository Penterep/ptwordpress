from tqdm import tqdm
from time import sleep
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
        was_blocked = False
        block_wait = self.args.block_wait

        for username in usernames:
            if block_wait is not None:
                logins, status = self._test_user_with_block_wait(username, weak_passwords, block_wait)
            else:
                logins, status = self._test_user_threaded(username, weak_passwords)

            successful_logins.extend(logins)
            if status == "blocked":
                was_blocked = True
                if block_wait is None:
                    return successful_logins, "blocked"

        return successful_logins, "blocked" if was_blocked else "completed"

    def _test_user_threaded(self, username, weak_passwords):
        successful_logins = []
        executor = ThreadPoolExecutor(max_workers=self.args.threads)
        try:
            futures = [executor.submit(self.attempt_login, username, pw) for pw in weak_passwords]

            for future in tqdm(as_completed(futures), total=len(futures), desc=f"Testing {username}", leave=False):
                try:
                    username, password, result = future.result()
                except Exception:
                    executor.shutdown(wait=True, cancel_futures=True)
                    return successful_logins, "blocked"

                if result == "success":
                    successful_logins.append((username, password))
                if result == "blocked":
                    executor.shutdown(wait=True, cancel_futures=True)
                    return successful_logins, "blocked"
        finally:
            executor.shutdown(wait=True)

        return successful_logins, "completed"

    def _test_user_with_block_wait(self, username, weak_passwords, block_wait):
        successful_logins = []
        was_blocked = False

        for password in tqdm(weak_passwords, total=len(weak_passwords), desc=f"Testing {username}", leave=False):
            username, password, result = self.attempt_login(username, password)

            if result == "success":
                successful_logins.append((username, password))
            if result == "blocked":
                was_blocked = True
                sleep(block_wait / 1000.0)

        return successful_logins, "blocked" if was_blocked else "completed"

    def attempt_login(self, username, password):
        payload = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': f'{self.args.url.rstrip("/")}/wp-admin/',
            'testcookie': '1'
        }

        try:
            response = self.http_client.send_request(self.login_url, method="POST", data=payload)
        except Exception:
            return (username, password, "blocked")

        cookie_header = response.headers.get('Set-Cookie', '')

        if 'wordpress_logged_in' in cookie_header:
            return (username, password, "success")

        if response.status_code in (403, 429):
            return (username, password, "blocked")

        response_text = response.text.lower()
        if "captcha" in response_text or "blocked" in response_text:
            return (username, password, "blocked")

        return (username, password, "fail")
