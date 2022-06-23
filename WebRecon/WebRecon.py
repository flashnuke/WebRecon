import os
import queue
import urllib.parse
import argparse
import threading
import pprint

from typing import Tuple, List, Callable, Type
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
#                 "ContentScanner": {
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
#                 "NmapScanner": {
#                   ```nmap scan report format```
#               }
#             },
#         }
#
#
#   --------------------------------------------------------------------------------------------------------------------


class WebRecon(ScanManager):
    _SCANNAME_TO_METHOD_MAP = {
        "nmap_scan": NmapScanner,
        "content_brute": ContentScanner
    }

    def __init__(self,
                 target_url: str,
                 scan_names: List[str],
                 dns_recursion=False,
                 *args, **kwargs):
        get_tld_names()

        self._scans = self._parse_scan_list(scan_names)

        self.scheme, self.subdomain, self.target_hostname = self._parse_target_url(target_url)
        self._default_scanner_args = {
            "scheme": self.scheme,
            "target_hostname": self.target_hostname
        }

        self.domains = queue.Queue()
        self.dns_recursion = dns_recursion

        self.recon_results = dict()

        super().__init__(target_url=self.generate_url_base_path(self.subdomain),
                         *args, **kwargs, **self._default_scanner_args)

    def _parse_scan_list(self, scan_list: List[str]) -> List[Type[Scanner]]:
        scans = list()
        for scan_name in scan_list:
            scanner = self._SCANNAME_TO_METHOD_MAP.get(scan_name, None)
            if not scanner:
                raise Exception("Bad scanner name")  # TODO exceptions
            scans.append(scanner)
        return scans

    def _parse_target_url(self, target_url: str) -> Tuple[str, str, str]:
        parsed_target = urllib.parse.urlparse(target_url)
        scheme = parsed_target.scheme
        netloc = parsed_target.netloc
        sub = netloc.split(".")[0] if self._contains_subdomain(target_url) else ScannerDefaultParams.DefaultSubdomain
        hostname = netloc.split(".", 1)[-1] if self._contains_subdomain(target_url) else netloc

        return scheme, sub, hostname

    def _start_scans_for_target(self, target: str) -> List[threading.Thread]:
        scanner_threads = list()
        for scanner in self._scans:
            scanner_name = scanner.__name__
            self._log(f"preparing a thread for {scanner_name}...")
            t = threading.Thread(target=self._do_scan(scanner, scanner_name, target))
            t.start()
            scanner_threads.append(t)
        return scanner_threads

    def start_recon(self):
        domains = self._setup_targets()
        self._log(f"found {domains.qsize()} domains")

        success_count, total_count = 0, 0
        while not domains.empty():
            target = domains.get()
            if total_count and target == self.target_url:
                continue
            self._log(f"setting up for target {target}")

            self.recon_results[target] = dict()
            try:
                scanner_threads = self._start_scans_for_target(target)
                for t in scanner_threads:
                    t.join()
                self._log(f"finished, saving results... target {target}")
                success_count += 1
            except Exception as exc:
                self._log(f"exception {exc} for {target}, skipping...")
            finally:
                total_count += 1

        results_str = pprint.pformat(self.recon_results,
                                     compact=PPrintDefaultParams.Compact, width=PPrintDefaultParams.Width)
        self._log(f"results: {results_str}")
        self._log("saving results...")
        self._save_results(results_str)
        self._log(f"finished successfully {success_count} out of {total_count} targets, shutting down...")

    def _setup_targets(self) -> queue.Queue:
        domains = queue.Queue()
        domains.put(self.target_url)
        if self.dns_recursion:
            subdomain_scanner.DNSScanner(target_url=self.target_hostname, domains_queue=self.domains,
                                         **self._default_scanner_args).start_scanner()
        return domains

    def _do_scan(self, scanner_cls: Type[Scanner], scanner_name: str, target: str):
        self.recon_results[target][scanner_name] = dict()
        scanner = scanner_cls(target_url=target, **self._default_scanner_args)
        results = scanner.start_scanner()
        self.recon_results[target][scanner_name].update(results)

    def _get_results_filename(self, *args, **kwargs) -> str:
        return "results_summary.txt"

    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        path = os.path.join(self.output_folder,
                            self._format_name_for_path('.'))
        return path

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

    WebRecon(target_url="https://example.com",
             dns_recursion=True,
             scan_names=["content_brute", "nmap_scan"]).start_recon()
    # TODO only dns / only brute / etc...
    # TODO argparse help -> must be without "www" (also add "raise exc" if something) you can also wait for input and check it

    # TODO check COLOR:
    # TODO "Color.clear_entire_line()
    # TODO        Color.p(status)"