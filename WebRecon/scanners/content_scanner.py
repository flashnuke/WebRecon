import collections
import urllib.request
import urllib.parse
import threading
import queue
import time
from urllib.error import URLError
from WebRecon.exploiters.bypass_403 import Bypass403

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


class ContentScanner:
    _DEF_USERAGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/19.0"
    _DEF_WORD_EXT = []  # [".php", ".bak", ".orig", ".inc"]
    # TODO save into folder of hostname (if exists or make)
    _DEF_RESULTS_PATH = "/content_results/"

    def __init__(self, config_json):
        self.target_url = config_json.get("target_url")
        parsed_target = urllib.parse.urlparse(self.target_url)
        self.hostname = parsed_target.netloc.strip("w").strip(".")

        self.wordlist_path = config_json.get("wordlist_path")
        self.headers = {
            'User-Agent': self._DEF_USERAGENT
        }
        self.word_extensions = config_json.get("word_extensions", self._DEF_WORD_EXT)

        self.request_cooldown = config_json.get("request_cooldown", 1)
        self.thread_count = config_json.get("thread_count", 8)
        self.request_timeout = config_json.get("request_timeout", 1)

        self.words_queue: queue.Queue = self.load_words()

        self.save_results_to_file = config_json.get("save_results_to_file", False)

        self.try_bypass = config_json.get("try_bypass", False)
        if self.try_bypass:
            self.results_bypass = collections.defaultdict(dict)

            self.ret_results = collections.defaultdict(list)

    def load_words(self) -> queue.Queue:
        with open(self.wordlist_path, "r") as wl:
            words = queue.Queue()
            for word in wl.readlines():
                words.put(word.rstrip("\n"))
        return words

    def single_bruter(self):
        while not self.words_queue.empty():
            attempt = self.words_queue.get()
            attempt_list = list()

            # check if there is a file extension, if not then it's a directory we're bruting
            if "." not in attempt:
                attempt_list.append(f"/{attempt}/")
            else:
                attempt_list.append(f"/{attempt}")

                for extension in self.word_extensions:
                    attempt_post = "." + attempt.split(".")[-1]

                    if attempt_post != extension:
                        attempt_list.append(f"/{attempt.replace(attempt_post, extension)}")

            for brute in attempt_list:
                path = urllib.parse.quote(brute)
                url = f"{self.target_url}{path}"

                try:

                    req = urllib.request.Request(url, headers=self.headers)
                    response = urllib.request.urlopen(req, timeout=self.request_timeout)
                    scode = response.code

                    if len(response.read()):
                        print(f"[{scode}] -> {url}")
                        self.save_results(scode, url)

                    if scode == 403 and self.try_bypass:
                        self.results_bypass[url] = Bypass403(self.target_url, path).start_bypasser()
                        self.save_results("bypass", str(self.results_bypass[url]))

                except URLError as url_exc:
                    if hasattr(url_exc, 'code') and url_exc.code != 404:  # this might indicate something interesting
                        print(f"[{url_exc.code}] -> {url}")
                        self.save_results(url_exc.code, url)

                except Exception as exc:
                    print(f"[!] - exception {exc} for {url}")

                finally:
                    time.sleep(self.request_cooldown)

    def save_results(self, code, url):
        results_filename = f'WebBruter_{self.hostname.replace(".", "_")}.txt'

        if self.save_results_to_file:
            with open(f"{self._DEF_RESULTS_PATH}{code}_{results_filename}", "a") as res_file:
                res_file.write(f"\n{url} -> {code}")

        self.ret_results[code].append(url)

    def start_scanner(self):
        threads = list()
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.single_bruter)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return self.ret_results


if __name__ == "__main__":
    config_path = None  # sys.argv[1]
    targetlist_path = "../../../blackhat-python/web_attacks/web_recon/targets/ps_sites.txt"  # sys.argv[2]
    website_targets = [i.strip("\n") for i in open(targetlist_path, "r").readlines()]

    for website in website_targets:
        ex_conf = {
            "target_url": website,
            "wordlist_path": "../../test_webcontent.txt",
            "results_filename": "results_bruter.txt",
            "request_cooldown": 0.1,
            "thread_count": 4
        }
        bruter = ContentScanner(ex_conf)
        bruter.start_scanner()
