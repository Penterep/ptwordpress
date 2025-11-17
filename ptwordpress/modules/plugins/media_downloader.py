from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import requests
import os
from ptlibs import ptprinthelper
from ptlibs.http.http_client import HttpClient


class MediaDownloader:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.save_path = os.path.abspath(self.args.save_media)
        os.makedirs(self.save_path, exist_ok=True)
        self.http_client = HttpClient(self.args, self.ptjsonlib)

    def _download_file(self, url):
        try:
            response = self.http_client.send_request(url, method="GET", stream=True)
            response.raise_for_status()
            filename = url.split("/")[-1]
            with open(os.path.join(self.save_path, filename), "wb") as file:
                for chunk in response.iter_content(chunk_size=1024):
                    file.write(chunk)
        except requests.RequestException as e:
            print(f"Error downloading {url}: {e}")

    def save_media(self, links: list):
        ptprinthelper.ptprint("Saving media", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)

        with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
            list(tqdm(pool.map(self._download_file, links), total=len(links), desc="Progress", unit_scale=False, leave=False, bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}"))
            ptprinthelper.ptprint(f"Media saved successfully to {self.save_path}/", "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

