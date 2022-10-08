import collections
import urllib.parse
import threading
import time
import requests

from typing import Any, Dict
from urllib3.exceptions import HTTPError

from .base_scanner import Scanner, ScanManager
from .utils import *
from .bypass_403 import Bypass403

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan websites for vulnerable directories or files by bruteforce
#
#   --------------------------------------------------------------------------------------------------------------------


class ContentScanner(Scanner):
    SCAN_NICKNAME = ScannerNames.ContentScan
    _SCAN_COLOR = OutputColors.Blue
    _SUPPORTS_CACHE = True
    _WRITE_RESULTS = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ret_results: Dict[Union[int, str], Union[Dict, List]] = collections.defaultdict(list)

        self.do_bypass = kwargs.get("do_bypass", False)
        if self.do_bypass:
            for scode in ScannerDefaultParams.SuccessStatusCodes:
                self.ret_results[f'bypass {scode}'] = list()

    def _save_results(self, *args, **kwargs):
        results_str = str()
        for code, urls in self.ret_results.items():
            results_str += f"{code} status code\n\n"
            for url in urls:
                results_str += f"{url}\n"
            results_str += "\n\n================================\n\n"
        super()._save_results(results_str, mode='w')

    def single_bruter(self):
        attempt_list = list()
        while not self.words_queue.empty() and not ScanManager._SHOULD_ABORT:
            attempt = self.words_queue.get().strip("/")
            found_any = False

            attempt_list.append(f"/{attempt}")
            if "." in attempt:  # check if there is a file extension
                if ScannerDefaultParams.FileExtensions:
                    for extension in ScannerDefaultParams.FileExtensions:
                        attempt_post = "." + attempt.split(".")[-1]

                        if attempt_post != extension:
                            attempt_list.append(f"/{attempt.replace(attempt_post, extension)}")
            else:
                attempt_list.append(f"/{attempt}/")

            for brute in attempt_list:
                path = urllib.parse.quote(brute)
                url = f"{self.target_url}{path}"

                try:
                    response = self._make_request(method="GET", url=url)
                    scode = response.status_code

                    if scode == ScannerDefaultParams.ForbiddenSCode and self.do_bypass:
                        bypass_results = Bypass403(target_url=self.target_url,
                                                   target_keyword=path,
                                                   target_hostname=self.target_hostname,
                                                   scheme=self.scheme).start_scanner()
                        for bypass_scode, bypass_urls in bypass_results.items():
                            self.ret_results[f'bypass {scode}'].extend(bypass_urls)
                            found_any = True

                    if scode in ScannerDefaultParams.SuccessStatusCodes:  # after bypass to make sure we save all results
                        self.ret_results[scode].append(url)
                        self._log_progress(f"{path} -> [{scode}]")
                        found_any = True

                except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                        requests.exceptions.ReadTimeout, HTTPError):
                    continue
                except requests.exceptions.TooManyRedirects:
                    self.ret_results[ScannerDefaultParams.TooManyRedirectsSCode].append(url)
                    self._log_progress(f"{path} -> [{ScannerDefaultParams.TooManyRedirectsSCode}]")
                    found_any = True
                except Exception as exc:
                    self.abort_scan(reason=f"target {url}, exception - {exc}")
                finally:
                    if found_any:
                        self._save_results()
                    time.sleep(self.request_cooldown)

            attempt_list.clear()
            self._update_count(attempt, found_any)

    def _start_scanner(self):
        threads = list()
        self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)

        for _ in range(self.thread_count):
            t = threading.Thread(target=self.single_bruter)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        self._save_results()
        return self.ret_results

    def _define_status_output(self) -> Dict[str, Any]:
        status = super()._define_status_output()
        status[OutputStatusKeys.ResultsPath] = self.truncate_str(self.results_path_full)
        status[OutputStatusKeys.Current] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Progress] = OutputValues.EmptyProgressBar
        status[OutputStatusKeys.Left] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Found] = OutputValues.ZeroStatusVal

        return status


if __name__ == "__main__":
    pass
