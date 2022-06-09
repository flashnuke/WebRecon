from scanners import *
import threading
from typing import Dict, List
from copy import deepcopy
import pprint

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


class WebRecon:
    def __init__(self, target: str):
        self.target = target
        self.domains = None
        self.domains_count = 0

        self.recon_results = {
            "content_brute": dict(),
            "nmap_scan": dict()
        }

    def perform_dns_scan(self):
        dns_scan_conf = {  # todo def params wordlist
            "target_url": self.target,
            "wordlist_path": "../../wordlists/subdomain_brute.txt",
            "request_cooldown": 0.1,
            "thread_count": 4
        }
        return subdomain_scanner.DNSScanner(dns_scan_conf).start_scanner()

    def start_recon(self):
        print(f"[*] starting DNS scan...")
        self.domains = self.perform_dns_scan()
        self.domains_count = self.domains.qsize()
        print(f"[*] found {self.domains_count} domains")

        successes = 0
        while not self.domains.empty():
            target = self.domains.get()
            try:
                results_cb, results_nmap = dict(), dict()

                print(f"[*] starting content brute for {target}...")
                t_cb = threading.Thread(target=self.do_content_brute, args=(target, results_cb))
                t_cb.start()

                print(f"[*] starting nmap port scanning for {target}...")
                t_nmap = threading.Thread(target=self.do_nmap_scan, args=(target, results_cb))
                t_nmap.start()

                t_cb.join()
                t_nmap.join()
                print(f"[*] finished, saving results for {target}...")

                self.recon_results[target] = dict()
                self.recon_results[target]["content_brute"] = deepcopy(results_cb)
                self.recon_results[target]["nmap_scan"] = deepcopy(results_nmap)
                successes += 1
            except Exception as exc:
                print(f"[!] exception {exc} for {target}, skipping...")

        print(f"[*] finished {successes}/{self.domains_count} subdomain targets, shutting down...")

    def do_content_brute(self, target, results):
        # todo params
        conf = {
            "target_url": target,
            "wordlist_path": "../../wordlists/webcontent_brute.txt",
            "save_results_to_file": False,
            "request_cooldown": 0.1,
            "thread_count": 4
        }
        bruter = content_scanner.ContentScanner(conf)
        results = bruter.start_scanner()

    def do_nmap_scan(self, target, results):
        conf = {
            "target_url": target,
            "save_results_to_file": False,
            "cmdline_args": "-sV, -sU, -sS",
            "ports": "22-443"
        }
        scanner = nmap_scanner.NmapScanner(conf)
        results = scanner.start_scanner()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Perform web reconnaissance on all subdomains of a given host.')
    parser.add_argument('target_url', metavar='t', type=str, nargs='+',
                        help='target url (subdomain will be stripped)')
    parser.add_argument('--do-dnmap', dest='do_nmap', action='store_const',
                        const=sum, default=max,
                        help='perform an nmap scan')

    args = parser.parse_args()
    print(args.accumulate(args.integers))

    # WebRecon("https://example.com")
