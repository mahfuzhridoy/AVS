import requests
import copy
import re
from urllib.parse import urlparse, parse_qs

requests.packages.urllib3.disable_warnings()


class InjectionDetector:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.marker = "CTXTEST123"

    def detect(self, url, method="GET", params=None, data=None, headers=None, cookies=None):
        params = params or {}
        data = data or {}
        headers = headers or {}
        cookies = cookies or {}

        results = []

        url, url_params = self._extract_url_params(url)
        params.update(url_params)

        results += self._scan_params(url, method, params, data, headers, cookies, "query")
        results += self._scan_params(url, method, params, data, headers, cookies, "body")
        results += self._scan_headers(url, method, params, data, headers, cookies)
        results += self._scan_cookies(url, method, params, data, headers, cookies)

        return results

    def _extract_url_params(self, url):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        clean_url = url.split("?")[0]
        flat_params = {k: v[0] for k, v in query_params.items()}
        return clean_url, flat_params

    def _scan_params(self, url, method, params, data, headers, cookies, location):
        results = []
        target_dict = params if location == "query" else data

        for key in target_dict:
            test_params = copy.deepcopy(params)
            test_data = copy.deepcopy(data)

            if location == "query":
                test_params[key] = self.marker
            else:
                test_data[key] = self.marker

            response = self._send_request(url, method, test_params, test_data, headers, cookies)
            if not response:
                continue

            if self.marker in response.text:
                contexts = self._classify_context(response.text)
                confidence = self._calculate_confidence(contexts)

                results.append({
                    "param": key,
                    "location": location,
                    "reflected": True,
                    "contexts": contexts,
                    "confidence": confidence
                })

        return results

    def _scan_headers(self, url, method, params, data, headers, cookies):
        results = []
        common_headers = ["User-Agent", "Referer", "X-Forwarded-For"]

        for header in common_headers:
            test_headers = copy.deepcopy(headers)
            test_headers[header] = self.marker

            response = self._send_request(url, method, params, data, test_headers, cookies)
            if not response:
                continue

            if self.marker in response.text:
                contexts = self._classify_context(response.text)
                confidence = self._calculate_confidence(contexts)

                results.append({
                    "param": header,
                    "location": "header",
                    "reflected": True,
                    "contexts": contexts,
                    "confidence": confidence
                })

        return results

    def _scan_cookies(self, url, method, params, data, headers, cookies):
        results = []

        for key in cookies:
            test_cookies = copy.deepcopy(cookies)
            test_cookies[key] = self.marker

            response = self._send_request(url, method, params, data, headers, test_cookies)
            if not response:
                continue

            if self.marker in response.text:
                contexts = self._classify_context(response.text)
                confidence = self._calculate_confidence(contexts)

                results.append({
                    "param": key,
                    "location": "cookie",
                    "reflected": True,
                    "contexts": contexts,
                    "confidence": confidence
                })

        return results

    def _send_request(self, url, method, params, data, headers, cookies):
        try:
            if method.upper() == "POST":
                return requests.post(url, params=params, data=data,
                                     headers=headers, cookies=cookies,
                                     timeout=self.timeout, verify=False)
            else:
                return requests.get(url, params=params,
                                    headers=headers, cookies=cookies,
                                    timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None

    def _classify_context(self, text):
        contexts = []

        if re.search(f">{self.marker}<", text):
            contexts.append("html")

        if re.search(f'=["\']{self.marker}["\']', text):
            contexts.append("attribute")

        if re.search(f"<script[^>]*>.*{self.marker}.*</script>", text, re.DOTALL):
            contexts.append("js")

        if re.search(f"(href|src)=['\"].*{self.marker}", text):
            contexts.append("url")

        if re.search(f"<!--.*{self.marker}.*-->", text):
            contexts.append("comment")

        return list(set(contexts))

    def _calculate_confidence(self, contexts):
        if "js" in contexts:
            return "high"
        elif "attribute" in contexts:
            return "medium"
        elif "html" in contexts:
            return "medium"
        elif contexts:
            return "low"
        return "low"