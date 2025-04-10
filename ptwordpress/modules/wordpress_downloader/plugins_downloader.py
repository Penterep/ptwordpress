import os
import json
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

class WordpressPluginsDownloader:
    def __init__(self, args, ptjsonlib, download_path=None):
        """
        Initializes the WordpressPluginsDownloader.

        This constructor determines the correct file path to save the plugin wordlist.
        - If `download_path` is `True`, the default path '../wordlists/plugins.txt' is used.
        - If a directory is provided, 'plugins.txt' will be created in that directory.
        - If only a filename is provided, the file is created in the current working directory.
        - If a full file path is provided, it is used directly.

        The method ensures the path is valid, writable, and prepares the file for writing.

        Args:
            args: Arbitrary arguments passed to the downloader (custom use).
            ptjsonlib: Utility library expected to contain an `end_error` method for error handling.
            download_path (str or bool, optional): Path to a directory, a filename, or a full path.
                                                   If True, default path is used.

        Raises:
            SystemExit: If the path is not writable or cannot be created.
        """
        if not download_path:
            return

        if download_path is True:
            # Use default path if True is passed
            self.output_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'plugins.txt'))
        else:
            # Normalize user-provided path
            download_path = os.path.expanduser(str(download_path))    # Support for ~/ paths

            if os.path.isdir(download_path):
                # It's a directory -> save to plugins.txt inside it
                self.output_file = os.path.join(download_path, 'plugins.txt')
            elif os.path.basename(download_path) == download_path:
                # It's just a filename (no directory part) -> save to current working directory
                self.output_file = os.path.join(os.getcwd(), download_path)
            else:
                # It's a full file path
                self.output_file = download_path

        try:
            # Create directory if it doesn't exist and ensure file exists
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            with open(self.output_file, 'a'):
                os.utime(self.output_file, None)
        except Exception as e:
            ptjsonlib.end_error(f"Cannot create or access the file: {e}")
            sys.exit(1)

        if not os.access(self.output_file, os.W_OK):
            ptjsonlib.end_error("File is read only.")
            sys.exit(1)

        self.args = args
        self.wordlist_path = self.output_file
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
        try:
            initial_data = initial_response.json()
        except Exception as e:
            #print(e)
            return
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