import requests
import threading
import queue
import time

from urllib3.exceptions import HTTPError
from .utils import *
from .base_scanner import Scanner, ScanManager
from functools import lru_cache
from typing import Dict, Any

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan for subdomains
#
#   --------------------------------------------------------------------------------------------------------------------


class DNSScanner(Scanner):
    SCAN_NICKNAME = ScannerNames.DnsScan
    _SCAN_COLOR = OutputColors.Blue
    _SUPPORTS_CACHE = True
    _WRITE_RESULTS = True

    def __init__(self, domains_queue=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.domains_queue = domains_queue if domains_queue else queue.Queue()

    def single_bruter(self):

        while not self.words_queue.empty() and not ScanManager._SHOULD_ABORT:
            url_path = self.generate_url_base_path(self.words_queue.get())
            found = False
            try:
                res = self._make_request(method="GET", url=url_path)
                found = res.status_code
                if found:
                    self._save_results(f"{url_path}\n")
                    self.domains_queue.put(url_path)
            except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                    requests.exceptions.ReadTimeout, HTTPError):
                # other exceptions should not occur
                continue
            except Exception as exc:
                self.abort_scan(reason=f"target {url_path}, exception - {exc}")
            finally:
                self._update_count(url_path, found)
                time.sleep(self.request_cooldown)

    def _start_scanner(self) -> queue.Queue:
        threads = list()
        self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)

        for _ in range(self.thread_count):
            t = threading.Thread(target=self.single_bruter)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return self.domains_queue
    
    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        path = os.path.join(self.results_path,
                            self._format_name_for_path(self.target_hostname))

        return path

    def _define_status_output(self) -> Dict[str, Any]:
        status = super()._define_status_output()
        status[OutputStatusKeys.Current] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Progress] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Left] = OutputValues.EmptyStatusVal
        status[OutputStatusKeys.Found] = OutputValues.ZeroStatusVal

        return status


if __name__ == "__main__":
    pass
