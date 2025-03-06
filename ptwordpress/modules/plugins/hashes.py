from ptlibs import ptprinthelper
import hashlib
import requests

class Hashes:
    _instance = None
    def __new__(cls, args=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.args = args
        return cls._instance

    def __init__(self, args):
        self.emails = set()
        self.args = args

    def get_hashes_from_favicon(self, response = None):
        favicon_data = response.content
        # Vypočítat hashe
        hashes: dict = self.calculate_hashes(favicon_data)

        ptprinthelper.ptprint("Favicon.ico hashes (etag)", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)
        for hash_type, hash_value in hashes.items():
            ptprinthelper.ptprint(f"{hash_type}{' '*(10-len(hash_type))}{hash_value.lower()}", "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True, end="\n")

    def calculate_hashes(self, data):
        hashes = {
            'MD5': hashlib.md5(data).hexdigest(),
            'SHA1': hashlib.sha1(data).hexdigest(),
            'SHA2': hashlib.sha256(data).hexdigest(),
            'SHA256': hashlib.sha256(data).hexdigest(),
        }
        return hashes

def get_emails_instance(args):
    return Emails(args)

