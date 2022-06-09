import nmap
import urllib.parse
import collections
import pprint  # todo requirements

#   --------------------------------------------------------------------------------------------------------------------
#
#   Scan ports, OS and services on a given host using NMAP
#
#   TODO python-nmap==0.7.1 requirements (and other libs)
#   Notes
#       *
#
#   --------------------------------------------------------------------------------------------------------------------


class NmapScanner:
    # TODO save into folder of hostname (if exists or make)
    _DEF_RESULTS_PATH = "nmap_results"

    def __init__(self, config_json):
        self.target_url = config_json.get("target_url")
        self.hostname = urllib.parse.urlparse(self.target_url).netloc
        self.save_results_to_file = config_json.get("save_results_to_file", False)

        self.cmdline_args = config_json.get("cmdline_args", "-sV -sU -sS")
        self.ports = config_json.get("ports", "22-443")

        self.ret_results = collections.defaultdict(list)

    def save_results(self):
        results_filename = f'NmapScanner__{self.hostname.replace(".", "_")}.txt'

        if self.save_results_to_file:
            with open(f"{self._DEF_RESULTS_PATH}/{results_filename}", "a") as res_file:
                pprint.pprint(self.ret_results, res_file)

    def start_scanner(self):
        nm = nmap.PortScanner()
        nm.scan(hosts=self.hostname, ports=self.ports, arguments=self.cmdline_args)
        for host in nm.all_hosts():
            self.ret_results[host] = nm[host]
        pprint.pprint(self.ret_results)
        self.save_results()

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
