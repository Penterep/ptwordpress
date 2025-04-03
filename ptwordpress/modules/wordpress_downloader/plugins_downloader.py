import os
import json
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

class WordpressPluginsDownloader:
    def __init__(self, args, download_path=None):
        download_path = download_path
        if isinstance(download_path, bool):
            self.downloads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")
        else:
            if not download_path:
                return
            self.downloads_dir = os.path.join(download_path, "downloads")

        os.makedirs(self.downloads_dir, exist_ok=True)
        self.wordlist_path = os.path.join(self.downloads_dir, "plugins_big.txt")
        self.args = args
        self.existing_plugins = set()
        self.load_existing_plugins()

        print("Saving to:", self.wordlist_path)

    def load_existing_plugins(self):
        """Load existing plugins from the wordlist"""
        if os.path.exists(self.wordlist_path):
            with open(self.wordlist_path, "r") as f:
                self.existing_plugins = set(f.read().splitlines())
            print(f"Loaded {len(self.existing_plugins)} existing plugins from the wordlist.")
        else:
            print("No existing wordlist found. Starting fresh.")

    def run(self):
        self.fetch_plugins()

    def fetch_plugins(self):
        page = 1
        plugins = set()
        url_template = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&page={}"

        # Fetch the total number of pages first to set up tqdm
        print("Fetching initial page for total pages count...")
        initial_response = requests.get(url_template.format(1), proxies=self.args.proxy, verify=False if self.args.proxy else True)
        if initial_response.status_code != 200:
            print("Failed to fetch initial page")
            return

        initial_data = initial_response.json()
        total_pages = initial_data["info"].get("pages")

        print(f"Pages to download: {total_pages}")

        # Setup tqdm for the progress bar based on total pages
        with tqdm(total=total_pages, desc="Fetching plugins", unit="page", ncols=100, position=0, leave=True) as pbar:
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                future_to_page = {executor.submit(self.fetch_page_plugins, url_template, page, pbar): page for page in range(1, total_pages + 1)}

                for future in as_completed(future_to_page):
                    page = future_to_page[future]
                    try:
                        new_plugins = future.result()
                        if new_plugins:
                            self.save_wordlist(new_plugins)
                            plugins.update(new_plugins)
                    except Exception as e:
                        print(f"Error on page {page}: {e}")
                    pbar.update(1)

        print(f"Total new plugins fetched: {len(plugins)}")

    def fetch_page_plugins(self, url_template, page, pbar):
        url = url_template.format(page)
        response = requests.get(url, proxies=self.args.proxy, verify=False if self.args.proxy else True)

        if response.status_code == 200:
            data = response.json()
            page_plugins = [plugin["slug"] for plugin in data.get("plugins", [])]
            new_plugins = set(page_plugins) - self.existing_plugins
            return new_plugins
        else:
            print(f"Failed to fetch page {page}")
            return set()

    def save_wordlist(self, plugins):
        if plugins:
            with open(self.wordlist_path, "a") as f:
                f.write("\n".join(plugins) + "\n")

        self.existing_plugins.update(plugins)

        self.sort_wordlist()

    def sort_wordlist(self):
        file_path = self.wordlist_path
        with open(file_path, "r") as file:
            lines = file.readlines()
        lines.sort()
        with open(file_path, "w") as file:
            file.writelines(lines)