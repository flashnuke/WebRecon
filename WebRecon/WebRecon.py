from scanners import *
import threading
from typing import Dict, List
from copy import deepcopy
import pprint
from scanners import ScanManager

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


class WebRecon(ScanManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.domains = None
        self.domains_count = 0

        self.recon_results = {
            "content_brute": dict(),
            "nmap_scan": dict()
        }

    def start_recon(self):
        self.log("starting DNS scan...")
        self.domains = self._perform_dns_scan()
        self.domains_count = self.domains.qsize()
        self.log(f"found {self.domains_count} domains")

        success_count = 0
        while not self.domains.empty():
            target = self.domains.get()
            try:
                results_cb, results_nmap = dict(), dict()

                self.log(f"preparing a thread for content brute... target {target}")
                t_cb = threading.Thread(target=self._do_content_brute, args=(target, results_cb))
                t_cb.start()

                self.log(f"preparing a thread for nmap port scanning... target {target}")
                t_nmap = threading.Thread(target=self._do_nmap_scan, args=(target, results_cb))
                t_nmap.start()

                t_cb.join()
                t_nmap.join()
                self.log(f"finished, saving results... target {target}")

                self.recon_results[target] = dict()
                self.recon_results[target]["content_brute"] = deepcopy(results_cb)
                self.recon_results[target]["nmap_scan"] = deepcopy(results_nmap)
                success_count += 1
            except Exception as exc:
                self.log(f"exception {exc} for {target}, skipping...")

        self.log(f"finished {success_count} out of {self.domains_count} subdomain targets, shutting down...")

    def _perform_dns_scan(self):
        return subdomain_scanner.DNSScanner(target_url=self.target_url).start_scanner()

    def _do_content_brute(self, target, results):
        bruter = content_scanner.ContentScanner(target_url=target)
        results = bruter.start_scanner()
        self.log(f"finished content brute for {target}...")


    def _do_nmap_scan(self, target, results):
        scanner = nmap_scanner.NmapScanner(target_url=target)
        results = scanner.start_scanner()
        self.log(f"finished nmap port scanning for {target}...")


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
