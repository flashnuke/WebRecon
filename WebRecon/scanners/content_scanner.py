import collections
import urllib.parse
import threading
import time
from typing import Dict, List, Union
from .base_scanner import Scanner
from .utils import ScannerDefaultParams
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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.ret_results: Dict[str, Union[Dict, List]] = collections.defaultdict(list)
        self.try_bypass = kwargs.get("try_bypass", False)
        if self.try_bypass:
            self.ret_results['bypass'] = dict()
            self.results_bypass = collections.defaultdict(dict)

    def single_bruter(self):
        while not self.words_queue.empty():
            attempt = self.words_queue.get()
            attempt_list = list()

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
                        self._log(f"{url} = [{scode}] status code")
                        self.ret_results[scode].append(url)

                    if scode == 403 and self.try_bypass:
                        self.ret_results["bypass"] = Bypass403(target_url=self.target_url,
                                                               target_keyword=path,
                                                               target_hostname=self.target_hostname,
                                                               scheme=self.scheme).start_scanner()

                except Exception as exc:
                    self._log(f"exception {exc} for {url}")

                finally:
                    time.sleep(self.request_cooldown)

    def _start_scanner(self):
        threads = list()
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


if __name__ == "__main__":
    pass
