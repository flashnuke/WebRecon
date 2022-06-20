import nmap
import urllib.parse
import collections
import pprint  # todo requirements
from .base_scanner import Scanner

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan ports, OS and services on a given host using NMAP
#
#   TODO python-nmap==0.7.1 requirements (and other libs)
#   Notes
#       *
#
#   --------------------------------------------------------------------------------------------------------------------


class NmapScanner(Scanner):
    # TODO save into folder of hostname (if exists or make)
    _DEF_RESULTS_PATH = "nmap_results"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.save_results_to_file = kwargs.get("save_results_to_file", False)  # TODO ? to scanner?

        self.cmdline_args = kwargs.get("cmdline_args", "-sV")  # TODO revert to flags "-sV -sU -sS"
        self.ports = kwargs.get("ports", "22-443")

        self.ret_results = dict()

    # TODO save results below dont forget it
    # def _save_results(self):
    #     results_filename = f'NmapScanner__{self.hostname.replace(".", "_")}.txt'
    #
    #     if self.save_results_to_file:
    #         with open(f"{self._DEF_RESULTS_PATH}/{results_filename}", "a") as res_file:
    #             pprint.pprint(self.ret_results, res_file)

    def _start_scanner(self):
        nm = nmap.PortScanner()
        nm.scan(hosts=self.target_hostname, ports=self.ports, arguments=self.cmdline_args)
        for host in nm.all_hosts():
            self.ret_results[host] = nm[host]
        results_str = pprint.pformat(self.ret_results)
        self._log(f"\n{results_str}")
        self._save_results(results_str)

        return self.ret_results


if __name__ == "__main__":

    ex_conf = {
        "target_url": "http://scanme.nmap.org/",
        "save_results_to_file": True,
        "cmdline_args": "-sV",
        "ports": "1-65535"
    }
    bruter = NmapScanner(ex_conf)
    res = bruter.start_scanner()
