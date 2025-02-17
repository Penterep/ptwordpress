import re

class DualOutput:
    def __init__(self, terminal, file):
        self.terminal = terminal
        self.file = file

    def remove_ansi_escape_codes(self, text):
        # Regulární výraz pro hledání ANSI escape kódů
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

    def write(self, message):
        self.terminal.write(message)  # Výstup na terminál
        if self.file:
            self.file.write(self.remove_ansi_escape_codes(message))  # Výstup do souboru
        self.flush()  # Ihned po zápisu vyprázdnit buffer

    def flush(self):
        # Vyžaduje se pro kompatibilitu s print()
        self.terminal.flush()
        if self.file:
            self.file.flush()