class EngineLoader:
    def __init__(self, bug, payload_file=None):
        self.bug = bug
        self.payload_file = payload_file

    def load(self):
        if self.bug == "xss":
            from xss_engine import XSSEngine
            return XSSEngine(payload_file=self.payload_file)

        elif self.bug == "sqli":
            from sqli_engine import SQLiEngine
            return SQLiEngine(payload_file=self.payload_file)

        elif self.bug == "ssrf":
            from ssrf_engine import SSRFEngine
            return SSRFEngine(payload_file=self.payload_file)

        return None
