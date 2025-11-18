import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import csv
import hashlib
from ptlibs.http.http_client import HttpClient
import sys
from urllib.parse import urljoin

class VersionBySourcesIdentifier:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(self.args, self.ptjsonlib)

    def identify_version_by_sources(self):
        mapping_md5 = self.load_minimal_csv(os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "wordlists", "sources2versions.csv"))
        files = self.read_unique_list(os.path.join(os.path.join(os.path.abspath(__file__.rsplit("/", 1)[0]), "wordlists", "unique_sources_for_version_identify.txt")))
        aggregated_versions = set()
        matches_for_csv = []

        with ThreadPoolExecutor(max_workers=max(1, self.args.threads)) as ex:
            futures = {ex.submit(self.fetch_and_hash, self.args.url, path): path for path in files}
            for fut in as_completed(futures):
                res = fut.result()
                if res.get("status") != "ok" or not res.get("md5"):
                    continue

                file_path = res["file"]
                md5 = res["md5"].lower()
                # versions = set()
                versions = set(mapping_md5.get(md5, []))

                if not versions:
                    continue

                aggregated_versions.update(versions)
                matches_for_csv.append({
                    "File": file_path,
                    "URL": res.get("url",""),
                    "MD5": md5,
                    "Versions": ";".join(sorted(versions, key=self.version_sort_key)),
                    "HTTPStatus": res.get("http_status",""),
                })

        versions_list = sorted(aggregated_versions, key=self.version_sort_key)
        return versions_list
    

    def parse_version_tuple(self,ver_str, parts=4):
        if ver_str is None:
            ver_str = ""
        s = ver_str.strip()
        if s == "":
            vals = [0]
        else:
            parts_raw = [p for p in s.split('.') if p != ""]
            vals = []
            for p in parts_raw:
                try:
                    vals.append(int(p))
                except ValueError:
                    num = ""
                    for ch in p:
                        if ch.isdigit():
                            num += ch
                        else:
                            break
                    vals.append(int(num) if num else 0)
        if len(vals) < parts:
            vals = vals + [0] * (parts - len(vals))
        else:
            vals = vals[:parts]
        return tuple(vals)

    def version_sort_key(self, v):
        return self.parse_version_tuple(v, parts=4)

    def load_minimal_csv(self, path):
        mapping_md5 = defaultdict(set)
        try:
            with open(path, newline='', encoding='utf-8') as fh:
                reader = csv.DictReader(fh)
                fields = reader.fieldnames or []
                if "File" not in fields or "MD5" not in fields or "Version" not in fields:
                    raise SystemExit(f'CSV {path} musí obsahovat sloupce "Version","File","MD5". Dostupné: {fields}')
                for r in reader:
                    f = (r.get("File") or "").strip()
                    m = (r.get("MD5") or "").strip().lower()
                    v = (r.get("Version") or "").strip()
                    if not m or not v:
                        continue
                    mapping_md5[m].add(v)
        except FileNotFoundError:
            raise SystemExit(f'Nepodařilo se najít minimal CSV: {path}')
        return mapping_md5

    def read_unique_list(self, path):
        try:
            with open(path, encoding='utf-8') as fh:
                lines = [ln.strip() for ln in fh]
        except FileNotFoundError:
            raise SystemExit(f'Nepodařilo se najít unique list: {path}')
        out = []
        seen = set()
        for ln in lines:
            if not ln:
                continue
            if ln not in seen:
                out.append(ln); seen.add(ln)
        return out

    def fetch_and_hash(self, base, path):
        """
        Stáhne URL base + path a spočítá md5. Vrací slovník s informacemi.
        """
        url = urljoin(base.rstrip('/') + '/', path.lstrip('/'))
        try:
            r = self.http_client.send_request(url, method="GET")
        except Exception as e:
            return {"file": path, "url": url, "md5": "", "status": "error", "http_status": "", "error": str(e)}
        if r.status_code != 200:
            return {"file": path, "url": url, "md5": "", "status": "not_found", "http_status": r.status_code, "error": ""}
        md5 = hashlib.md5(r.content).hexdigest()
        return {"file": path, "url": url, "md5": md5, "status": "ok", "http_status": r.status_code, "error": ""}