import collections
import urllib.request
import urllib.parse
import threading
import queue
import time
from urllib.error import URLError
from .base_scanner import Scanner
from .exploiters import Bypass403
from functools import lru_cache

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

# TODO renew session to avoid 429? or handle 429 in such way that you retry?
# TODO change to requests lib
# TODO example below dict to kwargs


class ContentScanner(Scanner):
    _DEF_USERAGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/19.0"  # enum useragents
    _DEF_WORD_EXT = []  # [".php", ".bak", ".orig", ".inc"]
    # TODO save into folder of hostname (if exists or make)
    _DEF_RESULTS_PATH = "/content_results/"
    _DEF_WL_PATH = "scanners/wordlists/test_webcontent_brute.txt"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.headers = {
            'User-Agent': self._DEF_USERAGENT
        }

        self.wordlist_path = kwargs.get("wordlist_path", self._DEF_WL_PATH)  # TODO def

        self.word_extensions = kwargs.get("word_extensions", self._DEF_WORD_EXT)  # TODO DEF

        self.request_cooldown = kwargs.get("request_cooldown", 0.1)
        self.thread_count = kwargs.get("thread_count", 4)  # TODO by max threads count? OS cmd
        self.request_timeout = kwargs.get("request_timeout", 1)

        self.words_queue: queue.Queue = self.load_words()

        self.save_results_to_file = kwargs.get("save_results_to_file", False)  # TODO ? to scanner?

        self.try_bypass = kwargs.get("try_bypass", False)
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
                        self._log(f"{url} = [{scode}] status code")
                        self.ret_results[scode].append(url)

                    if scode == 403 and self.try_bypass:
                        self.results_bypass[url] = Bypass403(self.target_url, path).start_bypasser()
                        self.ret_results["bypass"].append(str(self.results_bypass[url]))

                except URLError as url_exc:
                    if hasattr(url_exc, 'code') and url_exc.code != 404:  # this might indicate something interesting
                        self._log(f"{url} = [{url_exc.code}] status code")
                        self.ret_results[url_exc.code].append(url)

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
        for code, urls in self.ret_results.items():  # TODO why doesnt save
            results_str += f"{code} status code\n\n"
            for url in urls:
                results_str += f"{url}\n"
            results_str += "\n\n================================\n\n"
        self._save_results(results_str)

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
