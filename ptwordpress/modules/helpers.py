def print_api_is_not_available(status_code):
    ptprinthelper.ptprint(f"API is not available" + (f" [{str(status_code)}]" if status_code else ""), "WARNING", condition=not self.args.json, indent=4)