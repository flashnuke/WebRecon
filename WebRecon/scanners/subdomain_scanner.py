import requests
import os
import threading
import queue
import time
from .base_scanner import Scanner
from functools import lru_cache

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan for subdomains
#
#   Notes
#       * Use a Queue in order to allow for multi-threading
#
#   Mitigation
#       *
#
#   --------------------------------------------------------------------------------------------------------------------


class DNSScanner(Scanner):
    _DEF_WL_PATH = "scanners/"

    def __init__(self, domains_queue=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.domains_queue = domains_queue if domains_queue else queue.Queue()

    def load_words(self) -> queue.Queue:
        with open(self.wordlist_path, "r") as wl:
            words = queue.Queue()
            for word in wl.readlines():
                words.put(word.rstrip("\n"))
        return words

    def single_bruter(self):
        while not self.words_queue.empty():
            url_path = self.generate_url_base_path(self.words_queue.get())

            try:
                res = self._make_request(method="GET", url=url_path)

                if res.status_code:
                    self._log(f"{url_path} = [{res.status_code}] status code")
                    self._save_results(f"{url_path}\n")
                    self.domains_queue.put(url_path)

            except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
                # other exceptions should not occur
                continue

            finally:
                time.sleep(self.request_cooldown)

    def _start_scanner(self) -> queue.Queue:
        threads = list()
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.single_bruter)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return self.domains_queue
    
    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        # overwrite the default output path
        path = os.path.join(self.results_path,
                            self._format_name_for_path(self.target_hostname))

        return path


if __name__ == "__main__":
    ex_conf = {
        "wordlist_path": "../../../wordlists/subdomain_brute.txt",
        "request_cooldown": 0.1,
        "thread_count": 4
    }
    bruter = DNSScanner(target_url="https://example.com")
    bruter.start_scanner()
