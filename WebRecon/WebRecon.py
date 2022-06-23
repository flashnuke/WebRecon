import os
import queue
import urllib.parse
import argparse
import threading
import pprint

from typing import Tuple
from scanners.utils import PPrintDefaultParams, ScannerDefaultParams
from functools import lru_cache
from scanners import *
from tld import get_tld, get_tld_names

# TODO lru imports maybe once using package?
# todo continue scan using cache?

#   --------------------------------------------------------------------------------------------------------------------
#
#   Perform a full web reconnaissance report
#
#   * Scan for content brute
#   * Test 403 with different bypass methods
#   * Nmap for open ports and services
#
#         self.recon_results = {
#             "domain_name": {
#                 "content_brute": {
#                     "code": [results],
#                     "code2": [results],
#                     "bypass": {
#                         "url": {
#                             "code": ["curl cmd"],
#                             "code2": ["curl_cmd"]
#                         },
#                         "url2": {
#                             "code": ["curl cmd"],
#                             "code2": ["curl_cmd"]
#                         }
#                     }
#                 }
#                 "nmap_scan": {
#                   ```nmap scan report format```
#               }
#             },
#         }
#
#
#   --------------------------------------------------------------------------------------------------------------------


class WebRecon(ScanManager):
    def __init__(self, target_url, dns_recursion=False, *args, **kwargs):
        get_tld_names()

        self.scheme, self.subdomain, self.target_hostname = self._parse_target_url(target_url)
        self._default_scanner_args = {
            "scheme": self.scheme,
            "target_hostname": self.target_hostname
        }

        self.domains = queue.Queue()
        self.dns_recursion = dns_recursion

        self.recon_results = dict()

        super().__init__(target_url=self.generate_urlpath(self.subdomain),
                         *args, **kwargs, **self._default_scanner_args)

    def _parse_target_url(self, target_url: str) -> Tuple[str, str, str]:
        parsed_target = urllib.parse.urlparse(target_url)
        scheme = parsed_target.scheme
        netloc = parsed_target.netloc
        sub = netloc.split(".")[0] if self._contains_subdomain(target_url) else ScannerDefaultParams.DefaultSubdomain
        hostname = netloc.split(".", 1)[-1] if self._contains_subdomain(target_url) else netloc

        return scheme, sub, hostname

    def start_recon(self):
        targets_count = self._setup_targets()
        self._log(f"found {targets_count} domains")

        success_count = 0
        while not self.domains.empty():
            target = self.domains.get()
            self.recon_results[target] = dict()

            try:
                self._log(f"preparing a thread for content scanning...")
                t_cb = threading.Thread(target=self._do_content_brute, args=(target,))
                t_cb.start()

                self._log(f"preparing a thread for nmap port scanning...")
                t_nmap = threading.Thread(target=self._do_nmap_scan, args=(target,))
                t_nmap.start()

                t_cb.join()
                t_nmap.join()
                self._log(f"finished, saving results... target {target}")

                success_count += 1
            except Exception as exc:
                self._log(f"exception {exc} for {target}, skipping...")

        results_str = pprint.pformat(self.recon_results,
                                     compact=PPrintDefaultParams.Compact, width=PPrintDefaultParams.Width)
        self._log(f"results: {results_str}")
        self._log("saving results...")
        self._save_results(results_str)
        self._log(f"finished {success_count} out of {targets_count} subdomain targets, shutting down...")

    def _setup_targets(self):
        self.domains.put(self.target_url)
        if self.dns_recursion:
            subdomain_scanner.DNSScanner(target_url=self.target_hostname, domains_queue=self.domains,
                                         **self._default_scanner_args).start_scanner()
        return self.domains.qsize()

    def _do_content_brute(self, target: str):
        bruter = content_scanner.ContentScanner(target_url=target, **self._default_scanner_args)
        results = bruter.start_scanner()
        self.recon_results[target]["content_brute"] = dict()
        self.recon_results[target]["content_brute"].update(results)

    def _do_nmap_scan(self, target: str):
        scanner = nmap_scanner.NmapScanner(target_url=target, **self._default_scanner_args)
        results = scanner.start_scanner()
        self.recon_results[target]["nmap_scan"] = dict()
        self.recon_results[target]["nmap_scan"].update(results)
    
    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        path = os.path.join(self.output_folder,
                            self.target_hostname.replace('.', '_'))
        return path

    def _get_results_filename(self, *args, **kwargs) -> str:
        return "results_summary.txt"

    @staticmethod
    def _contains_subdomain(target_url: str):
        return len(target_url.replace(f'.{get_tld(target_url)}', '').split('.')) > 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Add an argument
    # parser.add_argument('--name', type=str, required=True)
    # Parse the argument
    # args = parser.parse_args()
    # Print "Hello" + the user input argument
    # print('Hello,', args.name)

    WebRecon(target_url="https://example.com", dns_recursion=True).start_recon()
    # TODO only dns / only brute / etc...
    # TODO params like max thread count, etc, to external ENUM class
    # TODO argparse help -> must be without "www" (also add "raise exc" if something) you can also wait for input and check it
