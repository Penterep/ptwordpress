import ptlibs.ptprinthelper as ptprinthelper

"""
class Helpers:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
"""

def print_api_is_not_available(status_code):
    ptprinthelper.ptprint(f"API is not available" + (f" [{str(status_code)}]" if status_code else ""), "WARNING", condition=True, indent=4)