import os
import re
import requests
import zipfile
import hashlib
import json
from io import BytesIO
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.0.1"

class WordpressDownloader:
    def __init__(self, download_path=None):

        if not download_path:
            return

        if isinstance(download_path, bool):
            self.downloads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads", "wp")

        elif download_path:
            self.downloads_dir = os.path.join(download_path , "downloads", "wp")

        self.db_file = os.path.join(os.path.dirname(self.downloads_dir), "hashes.json")

        print("WP Download path:",  self.downloads_dir)
        os.makedirs(self.downloads_dir, exist_ok=True)
        self.max_parallel_downloads = 5
        self.main()

    def load_existing_hashes(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, "r") as f:
                return json.load(f)
        return {}

    def save_hashes(self, hashes):
        # Sort the dictionary by version (keys)
        sorted_hashes = dict(sorted(hashes.items(), key=lambda item: [int(x) for x in item[0].split('.')], reverse=True))

        with open(self.db_file, "w") as f:
            json.dump(sorted_hashes, f, indent=4)

    def save_existing_hashes(self, existing_hashes):
        # Filter only versions with existing hashes
        existing_only_hashes = {version: data['sha256'] for version, data in existing_hashes.items() if data['sha256']}

        # Modify versions to end with "x"
        modified_hashes = {}
        for version, hash_value in existing_only_hashes.items():
            major_minor = '.'.join(version.split('.')[:2])  # Get major.minor part
            modified_version = f"{major_minor}.x"  # Replace the patch version with "x"
            modified_hashes[modified_version] = hash_value


        # Save this filtered data to a new JSON file (optional)
        with open(os.path.join(os.path.dirname(self.downloads_dir), "release-badges-hashes.json"), "w") as f:
            json.dump(modified_hashes, f, indent=4)

        return modified_hashes

    def get_wordpress_versions(self):
        url = "https://wordpress.org/download/releases/"
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        versions = []

        # Regex to match versions in the format X.X and X.X.X
        for link in soup.find_all('a', href=True):
            match = re.search(r'wordpress-([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.zip', link['href'])
            if match:
                versions.append(match.group(1))

        # Remove duplicates and sort versions
        return sorted(set(versions), key=lambda v: [int(x) for x in v.split('.')], reverse=True)

    def compute_hash(self, data):
        return hashlib.sha256(data).hexdigest()

    def download_and_check_svg(self, version, existing_hashes):
        zip_url = f"https://wordpress.org/wordpress-{version}.zip"
        version_dir = os.path.join(self.downloads_dir, version)

        # Skip if already downloaded
        if os.path.exists(version_dir):
            print(f"{version} already downloaded.")
            return

        os.makedirs(version_dir, exist_ok=True)

        # Add tqdm for download progress
        zip_file_path = os.path.join(version_dir, f"wordpress-{version}.zip")
        with requests.get(zip_url, stream=True) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            with open(zip_file_path, 'wb') as f:
                for data in tqdm(response.iter_content(1024), total=total_size//1024, unit='KB', desc=f"Downloading {version}"):
                    f.write(data)

        if response.status_code == 200:
            with zipfile.ZipFile(zip_file_path) as z:
                svg_path = f"wordpress-{version}/wp-admin/images/about-release-badge.svg"
                if svg_path in z.namelist():
                    svg_data = z.read(svg_path)
                    hash_value = self.compute_hash(svg_data)
                    existing_hashes[version] = {'sha256': hash_value, 'has_svg': True}

                    # Create output folder and save SVG
                    output_dir = os.path.join("badges", version)
                    os.makedirs(output_dir, exist_ok=True)
                    with open(f"{output_dir}/about-release-badge.svg", "wb") as f:
                        f.write(svg_data)
                    print(f"Extracted {version}, hash: {hash_value}")
                else:
                    existing_hashes[version] = {'sha256': None, 'has_svg': False}
                    print(f"No badge found in {version}")
        else:
            print(f"Failed to download {version}")

    def download_versions_in_parallel(self, versions, existing_hashes):
        with ThreadPoolExecutor(max_workers=self.max_parallel_downloads) as executor:
            futures = [executor.submit(self.download_and_check_svg, version, existing_hashes) for version in versions]
            for future in tqdm(futures, desc="Downloading versions", total=len(versions)):
                future.result()

    def filter_versions(self, versions):
        """
        Filter out redundant minor versions. Only keep the highest version for each major.minor combination.
        """
        seen = set()
        filtered_versions = []

        for version in versions:
            major_minor = '.'.join(version.split('.')[:2])  # Extract the major.minor part
            if major_minor not in seen:
                filtered_versions.append(version)
                seen.add(major_minor)

        return filtered_versions

    def process_existing_downloads(self, existing_hashes):
        """
        If hashes.json is missing, go through the downloaded WordPress versions and rebuild the hashes.
        """
        for version_dir in os.listdir(self.downloads_dir):
            version_path = os.path.join(self.downloads_dir, version_dir)
            if os.path.isdir(version_path):
                # Process the version
                svg_path = f"wordpress/wp-admin/images/about-release-badge.svg"
                zip_file_path = os.path.join(version_path, f"wordpress-{version_dir}.zip")
                if os.path.exists(zip_file_path):
                    with zipfile.ZipFile(zip_file_path) as z:
                        if svg_path in z.namelist():
                            svg_data = z.read(svg_path)
                            hash_value = self.compute_hash(svg_data)
                            existing_hashes[version_dir] = {'sha256': hash_value, 'has_svg': True}
                            print(f"Recomputed {version_dir} hash: {hash_value}")
                        else:
                            existing_hashes[version_dir] = {'sha256': None, 'has_svg': False}
                            print(f"No badge found in {version_dir}")

    def main(self,):
        existing_hashes = self.load_existing_hashes()

        if not existing_hashes:
            print("hashes.json is missing, rebuilding from existing downloads...")
            self.process_existing_downloads(existing_hashes)

        versions = self.get_wordpress_versions()
        print(f"Found {len(versions)} versions")

        # Filter out redundant minor versions
        versions = self.filter_versions(versions)
        print(f"Filtered to {len(versions)} versions")

        # Only download versions that are not in the existing hashes or have not been downloaded
        versions_to_download = [version for version in versions if version not in existing_hashes or not os.path.exists(os.path.join(self.downloads_dir, version))]
        print(f"Downloading {len(versions_to_download)} versions")

        self.download_versions_in_parallel(versions_to_download, existing_hashes)

        self.save_hashes(existing_hashes)
        existing_hashes = self.save_existing_hashes(existing_hashes)

        print("\n", "SVG Hashes:", json.dumps(existing_hashes, indent=4), sep="\n")

if __name__ == "__main__":
    WordpressDownloader().main()