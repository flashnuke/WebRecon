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
    _DEF_RESULTS_PATH = "../dns_results/"  # TODO
    _DEF_WL_PATH = "scanners/wordlists/test_subdomain_brute.txt"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.results_queue = queue.Queue()

        self.headers = {
            'User-Agent': self._DEF_USERAGENT
        }

        self.wordlist_path = kwargs.get("wordlist_path", self._DEF_WL_PATH)  # TODO argparse ALSO use default wordlist path

        self.request_cooldown = kwargs.get("request_cooldown", 0.1)
        self.thread_count = kwargs.get("thread_count", 4)  # TODO by max threads count? OS cmd
        self.request_timeout = kwargs.get("request_timeout", 1)
        self.session = requests.Session()

        self.words_queue: queue.Queue = self.load_words()

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
                res = self.session.get(url=url_path, headers=self.headers, timeout=self.request_timeout)

                if res.status_code:
                    self._log(f"{url_path} = [{res.status_code}] status code")
                    self._save_results(f"\n{url_path}")
                    self.results_queue.put(url_path)

            except Exception as exc:  # TODO if exception is not related to dns, then print!! (i.e save file)
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
    def _get_results_directory(self) -> str:
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
    bruter = DNSScanner(ex_conf)
    bruter.start_scanner()
