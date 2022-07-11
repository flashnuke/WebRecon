import urllib.parse
import argparse
import threading
import pprint

from scanners.utils import Banner
from typing import Tuple, List, Type
from scanners import *
from tld import get_tld, get_tld_names

# TODO lru imports maybe once using package?
# todo continue scan using cache?
# every scan, when saving results, save cache... iterate over queue and save num of how manny were iterated upon
# make sure you verify the path of WL and the num of total WL beforehand

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
    _SCAN_COLOR = OutputColors.Orange

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
            # self._log(f"preparing a thread for {scanner_name}...")
            t = threading.Thread(target=self._do_scan(scanner, scanner_name, target))
            t.start()
            scanner_threads.append(t)
        return scanner_threads

    def start_recon(self):
        try:
            domains = self._setup_targets()
            domains_count = domains.qsize()
            self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)

            total_count = 0
            self._update_progress_status(total_count, domains_count)
            while not domains.empty():
                target = domains.get()
                if total_count and target == self.target_url:
                    continue
                self._log_status(OutputStatusKeys.Current, target)
                # self._log(f"setting up for target {target}")

                self.recon_results[target] = dict()
                try:
                    scanner_threads = self._start_scans_for_target(target)
                    for t in scanner_threads:
                        t.join()
                    # self._log(f"finished, saving results... target {target}")
                except Exception as exc:
                    self._log_exception(f"target {target} exception {exc}", False)
                finally:
                    total_count += 1
                    self._update_progress_status(total_count, domains_count)
                    results_str = pprint.pformat(self.recon_results,
                                                 compact=PPrintDefaultParams.Compact, width=PPrintDefaultParams.Width)
                    self._save_results(results_str, mode="w")

            self._log_status(OutputStatusKeys.State, OutputValues.StateComplete)

        except Exception as exc:
            self._log_status(OutputStatusKeys.State, OutputValues.StateFail)
            self._log_exception(exc, True)

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
        path = os.path.join(self.results_path,
                            self._format_name_for_path(self.target_hostname))
        return path

    @staticmethod
    def _contains_subdomain(target_url: str):
        return len(target_url.replace(f'.{get_tld(target_url)}', '').split('.')) > 1

    def _define_status_output(self) -> Dict[str, Any]:
        status = dict()
        status[OutputStatusKeys.State] = OutputValues.StateSetup
        status[OutputStatusKeys.Current] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Progress] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.ResultsPath] = self.results_path_full
        status[OutputStatusKeys.Left] = OutputValues.EmptyStatusVal

        return status

    @lru_cache()
    def _get_scanner_name(self) -> str:
        return str()


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
