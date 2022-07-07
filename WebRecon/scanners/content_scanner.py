import collections
import urllib.parse
import threading
import time
import requests
from typing import Any, Dict, List, Union

from urllib3.exceptions import HTTPError

from .base_scanner import Scanner
from .utils import *
from .bypass_403 import Bypass403

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan websites for vulnerable directories or files by bruteforce
#
#   TODO (scan web for websites with filters) -> (perform nmap) -> (perform content bruter) ->
#   TODO (bypass 403) -> (brute ftp / ssh) -> (brute admin pages)
#   TODO start with saving profile for each website: (subdomains), (ports), (vul pages + code)
#   TODO add .js ext? only if file ending? or not needed... (if ends with .js then do smth)
#   Notes
#       * Use a Queue in order to allow for multi-threading
#
#   Mitigation
#       *
#
#   --------------------------------------------------------------------------------------------------------------------


class ContentScanner(Scanner):
    _SCAN_COLOR = OutputColors.Blue

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._finished_counter = int()
        self._finished_counter_lock = threading.RLock()

        self._success_counter = int()
        self._success_counter_lock = threading.RLock()

        self._total_wordcount = self.words_queue.qsize()
        self.ret_results: Dict[str, Union[Dict, List]] = collections.defaultdict(list)

        self.try_bypass = kwargs.get("try_bypass", False)
        if self.try_bypass:
            self.ret_results['bypass'] = {scode: list() for scode in ScannerDefaultParams.SuccessStatusCodes}

    def _increment_finished_count(self):
        with self._finished_counter_lock:
            self._finished_counter += 1
            self._update_progress_status(self._finished_counter, self._total_wordcount)

    def _increment_success_count(self):
        with self._success_counter_lock:
            self._success_counter += 1
            self._log_status(OutputStatusKeys.Found, self._success_counter)

    def single_bruter(self):
        attempt_list = list()

        self._log_status(OutputStatusKeys.Left, self._total_wordcount - self._finished_counter)
        while not self.words_queue.empty():
            attempt = self.words_queue.get()
            self._log_status(OutputStatusKeys.Current, attempt)

            # check if there is a file extension, if not then it's a directory we're bruting
            if "." not in attempt:
                attempt_list.append(f"/{attempt}/")
            else:
                attempt_list.append(f"/{attempt}")

                for extension in ScannerDefaultParams.FileExtensions:
                    attempt_post = "." + attempt.split(".")[-1]

                    if attempt_post != extension:
                        attempt_list.append(f"/{attempt.replace(attempt_post, extension)}")

            for brute in attempt_list:
                path = urllib.parse.quote(brute)
                url = f"{self.target_url}{path}"

                try:
                    response = self._make_request(method="GET", url=url)
                    scode = response.status_code
                    if scode in ScannerDefaultParams.SuccessStatusCodes:
                        self.ret_results[scode].append(url)
                        self._increment_success_count()

                    if scode == 403 and self.try_bypass:  # TODO param 403
                        bypass_results = Bypass403(target_url=self.target_url,
                                                   target_keyword=path,
                                                   target_hostname=self.target_hostname,
                                                   scheme=self.scheme).start_scanner()
                        for bypass_scode, bypass_url in bypass_results.items():
                            self.ret_results["bypass"][bypass_scode].append(bypass_url)
                except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                        requests.exceptions.ReadTimeout, HTTPError):
                    continue
                except Exception as exc:
                    self._log_exception(f"target {url}, exception - {exc}", True)
                    raise exc
                finally:
                    self._increment_finished_count()
                    attempt_list.clear()
                    time.sleep(self.request_cooldown)

    def _start_scanner(self):
        threads = list()
        self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)

        for _ in range(self.thread_count):
            t = threading.Thread(target=self.single_bruter)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        results_str = str()
        for code, urls in self.ret_results.items():
            results_str += f"{code} status code\n\n"
            for url in urls:
                results_str += f"{url}\n"
            results_str += "\n\n================================\n\n"
        self._save_results(results_str)

        return self.ret_results

    def _define_status_output(self) -> Dict[str, Any]:
        status = dict()
        status[OutputStatusKeys.State] = OutputValues.StateSetup
        status[OutputStatusKeys.Current] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Progress] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.ResultsPath] = self.results_path_full
        status[OutputStatusKeys.Left] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Found] = OutputValues.ZeroStatusVal

        return status


if __name__ == "__main__":
    pass
