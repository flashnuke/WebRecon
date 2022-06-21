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
    _DEF_USERAGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/19.0"  # TODO ROTATING
    _DEF_WL_PATH = "scanners/wordlists/test_subdomain_brute.txt"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.results_queue = queue.Queue()

        self.wordlist_path = kwargs.get("wordlist_path", self._DEF_WL_PATH)  # TODO argparse ALSO use default wordlist path
        self.words_queue: queue.Queue = self.load_words()

        self.session = requests.Session()

    def generate_urlpath(self, dnsname):
        return f"{self.scheme}://{dnsname}.{self.target_hostname}"

    def load_words(self) -> queue.Queue:
        with open(self.wordlist_path, "r") as wl:
            words = queue.Queue()
            for word in wl.readlines():
                words.put(word.rstrip("\n"))
        return words

    def single_bruter(self):
        while not self.words_queue.empty():
            url_path = self.generate_urlpath(self.words_queue.get())

            try:
                res = self._make_request(method="GET", url=url_path)

                if res.status_code:
                    self._log(f"{url_path} = [{res.status_code}] status code")
                    self._save_results(f"{url_path}\n")
                    self.results_queue.put(url_path)

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

        return self.results_queue
    
    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        # overwrite the default output path
        path = os.path.join(self.output_folder,
                            self.target_hostname.replace('.', '_'))

        return path


if __name__ == "__main__":
    ex_conf = {
        "target_url": "https://www.wafa.ps",
        "wordlist_path": "../../../wordlists/subdomain_brute.txt",
        "request_cooldown": 0.1,
        "thread_count": 4
    }
    bruter = DNSScanner(target_url="https://example.com")
    bruter.start_scanner()
