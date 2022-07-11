import nmap
import pprint

from typing import Any, Dict
from .utils import *
from .base_scanner import Scanner

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan ports, OS and services on a given host using NMAP
#
#   Notes
#       *
#
#   --------------------------------------------------------------------------------------------------------------------


class NmapScanner(Scanner):
    _SCAN_COLOR = OutputColors.Blue
    _SUPPORTS_CACHE = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.cmdline_args = kwargs.get("cmdline_args", "-sV") + " >/dev/null"  # TODO ARGS and revert to flags "-sV -sU -sS"
        self.ports = kwargs.get("ports", "22-443")  # TODO ARGS

        self.ret_results = dict()

    def _start_scanner(self):
        self._log_status(OutputStatusKeys.State, OutputValues.StateRunning)

        nm = nmap.PortScanner()
        nm.scan(hosts=self.target_hostname, ports=self.ports, arguments=self.cmdline_args)
        for host in nm.all_hosts():
            self.ret_results[host] = nm[host]
        results_str = pprint.pformat(self.ret_results,
                                     compact=PPrintDefaultParams.Compact, width=PPrintDefaultParams.Width)
        self._save_results(results_str)

        return self.ret_results

    def _define_status_output(self) -> Dict[str, Any]:
        status = dict()
        status[OutputStatusKeys.State] = OutputValues.StateSetup  # TODO to super method state, path, cached
        status[OutputStatusKeys.ResultsPath] = self.results_path_full
        status[OutputStatusKeys.UsingCached] = OutputValues.BoolTrue if self._use_prev_cache else OutputValues.BoolFalse  # TODO method for general bool

        return status


if __name__ == "__main__":

    ex_conf = {
        "target_url": "http://scanme.nmap.org/",
        "cmdline_args": "-sV",
        "ports": "1-65535"
    }
    bruter = NmapScanner(ex_conf)
    res = bruter.start_scanner()
