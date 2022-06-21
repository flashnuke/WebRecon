import collections
import urllib.parse
import threading
import queue
import time
from .base_scanner import Scanner, ScannerDefaultParams
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

# TODO change to requests lib
# TODO example below dict to kwargs
# todo generate new user-agent headers after X (configurable) requests (renew session)


class ContentScanner(Scanner):
    _DEF_FILE_EXT = []  # [".php", ".bak", ".orig", ".inc"]
    _DEF_WL_PATH = "scanners/wordlists/test_webcontent_brute.txt"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.wordlist_path = kwargs.get("wordlist_path", self._DEF_WL_PATH)  # TODO def
        self.word_extensions = kwargs.get("word_extensions", self._DEF_FILE_EXT)  # TODO DEF
        self.words_queue: queue.Queue = self.load_words()

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
                    response = self._make_request(method="GET", url=url)
                    scode = response.status_code

                    if scode in ScannerDefaultParams.SuccessStatusCodes:
                        self._log(f"{url} = [{scode}] status code")
                        self.ret_results[scode].append(url)

                    if scode == 403 and self.try_bypass:
                        self.results_bypass[url] = Bypass403(self.target_url, path).start_bypasser()
                        self.ret_results["bypass"].append(str(self.results_bypass[url]))

                    if scode == 429:
                        time.sleep(ScannerDefaultParams.TooManyReqSleep)

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
