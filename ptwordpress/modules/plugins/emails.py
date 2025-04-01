import re
from ptlibs import ptprinthelper, ptmisclib

from modules.file_writer import write_to_file


class Emails:
    _instance = None
    def __new__(cls, args=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.args = args
        return cls._instance

    def __init__(self, args):
        self.args = args
        self.emails = set()
        self._tlds = ptmisclib.get_tlds()

    def parse_emails_from_response(self, response):
        """Retrieve emails from response"""
        response_text = response.text.replace(r"\r\n", " ").replace(r"\n", " ")

        email_regex = r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,3}"
        emails = re.findall(email_regex, response_text)

        for email in emails:
            email = email.lower()
            if any(email.endswith(f".{tld.lower()}") for tld in self._tlds):
                self.emails.add(email)

    def print_result(self):
        ptprinthelper.ptprint("Discovered e-mail addresses (from posts)", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)
        for email in sorted(list(self.emails)):
            ptprinthelper.ptprint(email, "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

        if not self.emails:
            ptprinthelper.ptprint("No email address found", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)

        if self.args.output:
            filename = self.args.output + "-emails.txt"
            write_to_file(filename, '\n'.join(sorted(self.emails)))

def get_emails_instance(args):
    return Emails(args)