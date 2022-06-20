import urllib.parse
import os
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


class ScanManager:
    _DEF_OUTPUT_DIRECTORY = "results"

    def __init__(self, *args, **kwargs):
        self.target_url = kwargs.get("target_url")
        if not self.target_url:
            raise Exception("Missing target url")  # TODO exceptions class?

        parsed_target = urllib.parse.urlparse(self.target_url)
        self.hostname = parsed_target.netloc.strip("w").strip(".")
        self.scheme = parsed_target.scheme
        if not self.scheme:
            raise Exception("Missing scheme url")  # TODO exceptions class?

        self.results_path = kwargs.get("output_path",
                                       f'{self._DEF_OUTPUT_DIRECTORY}/'
                                       f'{self.__class__.__name__}_{self.hostname.replace(".", "_")}.txt')

        try:
            os.remove(self.results_path)  # remove old files
        except FileNotFoundError:
            pass

    def log(self, text):
        # TODO with colors based on type of message
        print(f"[{self.hostname}] {(self.__class__.__name__ + ' ').ljust(20, '-')}> {text}")

    def save_results(self, results):
        with open(self.results_path, "a") as res_file:
            res_file.write(f"{results}")


class Scanner(ScanManager):
    _DEF_RESULTS_PATH = "../dns_results/"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def start_scanner(self) -> Any:
        try:
            self.log(f"starting scanner...")
            scan_results = self._start_scanner()
            self.log(f"scanner finished...")
            return scan_results
        except Exception as exc:
            self.log(f"aborting due to exception: {exc}")

    @abstractmethod
    def _start_scanner(self) -> Any:
        ...


if __name__ == "__main__":
    pass
