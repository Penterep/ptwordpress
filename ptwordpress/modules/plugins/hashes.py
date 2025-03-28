from ptlibs import ptprinthelper
import hashlib
import requests
import tempfile

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
        hashes: dict = self.calculate_hashes(response.content)

        ptprinthelper.ptprint("Favicon.ico hashes (etag)", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)
        for hash_type, hash_value in hashes.items():
            ptprinthelper.ptprint(f"{hash_type}{' '*(10-len(hash_type))}{hash_value.lower()}", "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True, end="\n")

    def calculate_hashes(self, data):
        hashes = {
            'MD5': hashlib.md5(data).hexdigest(),
            'SHA1': hashlib.sha1(data).hexdigest(),
            'SHA256': hashlib.sha256(data).hexdigest(),
        }
        return hashes

    def process_image_response(self, response):
        # Use NamedTemporaryFile with delete=True inside a context manager
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            # Write the response content directly to the temporary file
            temp_file.write(response.content)
            temp_file.flush()  # Ensure data is written to disk
            # Calculate the SHA256 hash using the already open file
            sha256_hash = self.calculate_sha256_from_file(temp_file)
        # The temporary file is automatically deleted after the with block
        return sha256_hash

    def calculate_sha256_from_file(self, file_obj):
        # Ensure the file pointer is at the beginning
        file_obj.seek(0)
        sha256_hash = hashlib.sha256()
        # Read the file in chunks to avoid using too much memory
        for byte_block in iter(lambda: file_obj.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()