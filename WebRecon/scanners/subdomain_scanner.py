import requests
import urllib.parse
import threading
import queue
import time
from .base_scanner import Scanner

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
    _DEF_USERAGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/19.0"
    _DEF_RESULTS_PATH = "../dns_results/"

    def __init__(self, config_json):
        self.target_url = config_json.get("target_url")
        parsed_target = urllib.parse.urlparse(self.target_url)
        self.hostname = parsed_target.netloc.strip("w").strip(".")
        self.scheme = parsed_target.scheme
        if not self.scheme:
            raise Exception(f"[!] Error: missing scheme for {self.target_url}")

        self.results_queue = queue.Queue()

        self.user_agent = config_json.get("user_agent", self._DEF_USERAGENT)
        self.headers = {
            'User-Agent': self._DEF_USERAGENT
        }

        self.request_cooldown = config_json.get("request_cooldown", 0.1)
        self.thread_count = config_json.get("thread_count", 4)
        self.request_timeout = config_json.get("request_timeout", 1)
        self.session = requests.Session()

        self.wordlist_path = config_json.get("wordlist_path")
        self.words_queue: queue.Queue = self.load_words()

    def generate_urlpath(self, dnsname):
        return f"{self.scheme}://{dnsname}.{self.hostname}"

    def load_words(self) -> queue.Queue:
        with open(self.wordlist_path, "r") as wl:
            words = queue.Queue()
            for word in wl.readlines():
                words.put(word.rstrip("\n"))
        return words

    def single_bruter(self):
        while not self.words_queue.empty():
            url_path = self.generate_urlpath(self.words_queue.get())
            print(url_path)

            try:
                res = self.session.get(url=url_path, headers=self.headers, timeout=self.request_timeout)

                if res.status_code:
                    print(f"[{res.status_code}] -> {url_path}")
                    self.save_results(url_path)
                    self.results_queue.put(url_path)

            except Exception as exc:
                continue

            finally:
                time.sleep(self.request_cooldown)

    def save_results(self, target_url):
        results_filename = f'DNSBruter_{self.hostname.replace(".", "_")}.txt'

        with open(f"{self._DEF_RESULTS_PATH}{results_filename}", "a") as res_file:
            res_file.write(f"\n{target_url}")

    def start_scanner(self) -> queue.Queue:
        threads = list()
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.single_bruter)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return self.results_queue


if __name__ == "__main__":
    ex_conf = {
        "target_url": "https://www.wafa.ps",
        "wordlist_path": "../../../wordlists/subdomain_brute.txt",
        "request_cooldown": 0.1,
        "thread_count": 4
    }
    bruter = DNSScanner(ex_conf)
    bruter.start_scanner()
