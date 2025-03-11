import re

class DualOutput:
    def __init__(self, terminal, file):
        self.terminal = terminal
        self.file = file

    def remove_ansi_escape_codes(self, text):
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

    def write(self, message):
        self.terminal.write(message)  # Output to terminal
        if self.file:
            self.file.write(self.remove_ansi_escape_codes(message))  # Output to file
        self.flush()  # Ihned po zápisu vyprázdnit buffer

    def flush(self):
        self.terminal.flush()
        if self.file:
            self.file.flush()