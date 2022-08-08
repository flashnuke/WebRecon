import nmap
import pprint

from typing import Any, Dict
from .utils import *
from .base_scanner import Scanner

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan ports, OS and services on a given host using NMAP
#
#   --------------------------------------------------------------------------------------------------------------------


class NmapScanner(Scanner):
    SCAN_NICKNAME = ScannerNames.NmapScan
    _SCAN_COLOR = OutputColors.Blue
    _SUPPORTS_CACHE = False
    _WRITE_RESULTS = True

    def __init__(self, *args, **kwargs):
        self.cmdline_args = kwargs.get("cmdline_args")
        super().__init__(*args, **kwargs)

        self.cmdline_args += " &>/dev/null"
        self.ports = kwargs.get("ports")

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
        status = super()._define_status_output()
        status[OutputStatusKeys.ResultsPath] = self.truncate_str(self.results_path_full)
        status["CmdlineArgs"] = self.cmdline_args
        return status


if __name__ == "__main__":
    pass
