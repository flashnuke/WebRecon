import os
import urllib.parse

from scanners import *
import threading
from typing import Dict, List
from copy import deepcopy
import pprint
from scanners import ScanManager
from functools import lru_cache

# TODO lru imports maybe once using package?
# TODO bruter class base abstract
# todo dnsclass and all other classes print start

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

# TODO rename content scan to endpoint scan?


class WebRecon(ScanManager):
    def __init__(self, *args, **kwargs):
        target_url = kwargs.get("target_url")
        parsed_target = urllib.parse.urlparse(target_url)
        self._default_scanner_args = {
            "target_hostname": parsed_target.netloc,
            "scheme": parsed_target.scheme
        }
        super().__init__(*args, **kwargs, **self._default_scanner_args)
        self.domains = None
        self.domains_count = 0

        self.recon_results = {
            "content_brute": dict(),
            "nmap_scan": dict()
        }

    def start_recon(self):
        self._do_dns_scan()
        self._log(f"found {self.domains_count} domains")

        success_count = 0
        while not self.domains.empty():
            target = self.domains.get()
            try:
                results_cb, results_nmap = dict(), dict()

                self._log(f"preparing a thread for content scanning...")
                t_cb = threading.Thread(target=self._do_content_brute, args=(target, results_cb))
                t_cb.start()

                self._log(f"preparing a thread for nmap port scanning...")
                t_nmap = threading.Thread(target=self._do_nmap_scan, args=(target, results_cb))
                t_nmap.start()

                t_cb.join()
                t_nmap.join()
                self._log(f"finished, saving results... target {target}")

                self.recon_results[target] = dict()
                self.recon_results[target]["content_brute"] = deepcopy(results_cb)
                self.recon_results[target]["nmap_scan"] = deepcopy(results_nmap)
                success_count += 1
            except Exception as exc:
                self._log(f"exception {exc} for {target}, skipping...")

        self._log(f"finished {success_count} out of {self.domains_count} subdomain targets, shutting down...")

    def _do_dns_scan(self):
        self.domains = subdomain_scanner.DNSScanner(target_url=self.target_url,
                                                    **self._default_scanner_args).start_scanner()
        self.domains_count = self.domains.qsize()

    def _do_content_brute(self, target, results):
        bruter = content_scanner.ContentScanner(target_url=target, **self._default_scanner_args)
        results = bruter.start_scanner()
        return results

    def _do_nmap_scan(self, target, results):
        scanner = nmap_scanner.NmapScanner(target_url=target, **self._default_scanner_args)
        results = scanner.start_scanner()
        return results
    
    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        # overwrite the default output path
        path = os.path.join(self.output_folder,
                            self.target_hostname.replace('.', '_'))
        return path

    def _get_results_filename(self, *args, **kwargs) -> str:
        return str()


if __name__ == "__main__":
    import argparse

    # parser = argparse.ArgumentParser(description='Perform web reconnaissance on all subdomains of a given host.')
    # parser.add_argument('target_url', metavar='t', type=str, nargs='+',
    #                     help='target url (subdomain will be stripped)')
    # parser.add_argument('--do-dnmap', dest='do_nmap', action='store_const',
    #                     const=sum, default=max,
    #                     help='perform an nmap scan')
    #
    # args = parser.parse_args()
    # print(args.accumulate(args.integers))

    WebRecon(target_url="https://example.com").start_recon()
    # TODO only dns / only brute / etc...
    # TODO params like max thread count, etc, to external ENUM class
    # TODO argparse help -> must be without "www" (also add "raise exc" if something) you can also wait for input and check it
    # TODO summary
