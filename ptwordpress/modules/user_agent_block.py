from ptlibs import ptprinthelper
from ptlibs.http.http_client import HttpClient
from modules.wp_paths import wp_directory_path


class UserAgentBlockTest:
    CONFIGURED_NAME = "configured"
    PYTHON_NAME = "python-requests"
    FIREFOX_NAME = "firefox"

    BLOCKED_STATUS_CODES = {401, 403, 406, 418, 429, 451, 503}
    PYTHON_REQUESTS_UA = "python-requests/2.32.3"
    FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

    def __init__(self, base_url, args, ptjsonlib):
        self.BASE_URL = base_url.rstrip("/")
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(self.args, self.ptjsonlib)

    def run(self):
        ptprinthelper.ptprint("User-Agent blocking detection", "TITLE", condition=not self.args.json, colortext=True, newline_above=True)

        user_agents = [
            (self.CONFIGURED_NAME, self._get_configured_user_agent()),
            (self.PYTHON_NAME, self.PYTHON_REQUESTS_UA),
            (self.FIREFOX_NAME, self.FIREFOX_UA),
        ]
        user_agents = self._deduplicate_user_agents(user_agents)
        endpoints = [
            ("HP", self.BASE_URL),
            ("feed", f"{self.BASE_URL}/feed"),
            ("wp-json", f"{self.BASE_URL}{wp_directory_path(self.args, 'json')}"),
        ]

        results_by_endpoint = []
        original_test_fpd = self.http_client.test_fpd
        original_store_urls = self.http_client._store_urls
        self.http_client.test_fpd = False
        self.http_client._store_urls = False
        try:
            for endpoint_name, url in endpoints:
                endpoint_results = []
                for label, user_agent in user_agents:
                    endpoint_results.append(self._check_url(endpoint_name, url, label, user_agent))
                results_by_endpoint.append({"name": endpoint_name, "url": url, "results": endpoint_results})
        finally:
            self.http_client.test_fpd = original_test_fpd
            self.http_client._store_urls = original_store_urls

        self._mark_user_agent_specific_blocks(results_by_endpoint)
        self._print_results(results_by_endpoint)

        results = [result for endpoint in results_by_endpoint for result in endpoint["results"]]
        default_blocked = [result for result in results if result["name"] == self.CONFIGURED_NAME and result["blocked"]]
        any_blocked = any(result["blocked"] for result in results)
        python_open = [result for result in results if result["name"] == self.PYTHON_NAME and not result["blocked"]]

        if any_blocked and python_open:
            endpoints_open = ", ".join(result["endpoint"] for result in python_open)
            ptprinthelper.ptprint(
                f"python-requests User-Agent is not blocked where another User-Agent was blocked: {endpoints_open}",
                "WARNING",
                condition=not self.args.json,
                indent=4,
                clear_to_eol=True,
            )

        self._print_blank_line()

        if default_blocked:
            details = "; ".join(f"{result['endpoint']} ({result['status']})" for result in default_blocked)
            self.ptjsonlib.end_error(f"Configured User-Agent is blocked: {details}", self.args.json)

    def _mark_user_agent_specific_blocks(self, results_by_endpoint):
        for endpoint in results_by_endpoint:
            endpoint_has_ok_response = any(result["ok"] for result in endpoint["results"])
            if not endpoint_has_ok_response:
                continue

            for result in endpoint["results"]:
                if not result["ok"]:
                    result["blocked"] = True

    def _print_results(self, results_by_endpoint):
        for index, endpoint in enumerate(results_by_endpoint):
            if index > 0:
                self._print_blank_line()

            ptprinthelper.ptprint(endpoint["url"], "TEXT", condition=not self.args.json, indent=4, clear_to_eol=True)
            for result in endpoint["results"]:
                tag = "WARNING" if result["blocked"] or not result["ok"] else "OK"
                ptprinthelper.ptprint(
                    f"{result['user_agent']} {result['status']}",
                    tag,
                    condition=not self.args.json,
                    indent=8,
                    clear_to_eol=True,
                )

    def _print_blank_line(self):
        ptprinthelper.ptprint(" ", None, condition=not self.args.json)

    def _check_url(self, endpoint_name, url, name, user_agent):
        headers = {"User-Agent": user_agent}
        try:
            response = self.http_client.send_request(
                url,
                method="GET",
                headers=headers,
                allow_redirects=True,
                max_retries=0,
                cache=False,
                store_urls=False,
                verbose=False,
            )
            status_code = getattr(response, "status_code", None)
            blocked = status_code in self.BLOCKED_STATUS_CODES
            ok = status_code is not None and 200 <= status_code < 400
            status = f"[{status_code}]" if status_code else "[no-status]"
        except Exception as error:
            blocked = True
            ok = False
            status = f"[no response: {error.__class__.__name__}]"

        return {
            "endpoint": endpoint_name,
            "name": name,
            "user_agent": user_agent,
            "status": status,
            "ok": ok,
            "blocked": blocked,
        }

    def _get_configured_user_agent(self):
        for key, value in (getattr(self.args, "headers", {}) or {}).items():
            if key.lower() == "user-agent":
                return value
        return self.args.user_agent

    def _deduplicate_user_agents(self, user_agents):
        deduplicated = []
        seen = set()
        for name, user_agent in user_agents:
            if user_agent in seen:
                continue
            seen.add(user_agent)
            deduplicated.append((name, user_agent))
        return deduplicated
