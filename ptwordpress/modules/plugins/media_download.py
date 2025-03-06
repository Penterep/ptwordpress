from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import requests
import os
from ptlibs import ptprinthelper

class MediaDownloader:
    def __init__(self, args):
        self.args = args
        self.save_path = os.path.abspath(self.args.save_media)
        os.makedirs(self.save_path, exist_ok=True)

    def _download_file(self, url):
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            filename = url.split("/")[-1]
            with open(os.path.join(self.save_path, filename), "wb") as file:
                for chunk in response.iter_content(chunk_size=1024):
                    file.write(chunk)
        except requests.RequestException as e:
            print(f"Error downloading {url}: {e}")

    def save_media(self, links: list):
        ptprinthelper.ptprint("Saving media", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(tqdm(pool.map(self._download_file, links), total=len(links), desc="Saving media", unit="B", unit_scale=True))
