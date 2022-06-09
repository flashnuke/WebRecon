import urllib.parse
from typing import Any

from abc import abstractmethod

#   --------------------------------------------------------------------------------------------------------------------
#
#   Base Scanner
#
#   Notes
#       *
#
#   Mitigation
#       *
#
#   --------------------------------------------------------------------------------------------------------------------


class Scanner:
    _DEF_RESULTS_PATH = "../dns_results/"

    def __init__(self, config_json):
        self.target_url = config_json.get("target_url")
        parsed_target = urllib.parse.urlparse(self.target_url)
        self.hostname = parsed_target.netloc.strip("w").strip(".")
        self.scheme = parsed_target.scheme

    @abstractmethod
    def start_scanner(self) -> Any:
        ...

    def save_results(self, filename, data):
        pass
        results_filename = f'DNSBruter_{self.hostname.replace(".", "_")}.txt'

        with open(f"{self._DEF_RESULTS_PATH}{results_filename}", "a") as res_file:
            res_file.write(f"\n{target_url}")


if __name__ == "__main__":
    pass
