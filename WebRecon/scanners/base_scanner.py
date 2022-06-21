import requests
import os
from typing import Any, Union
from pathlib import Path
from functools import lru_cache
from abc import abstractmethod
import threading
from enum import Enum
from .utils import *

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
    _LOGGER_MUTEX = threading.RLock()
    _DEF_OUTPUT_DIRECTORY = "results"
    _ACCEPTED_SCHEMES = ["http", "https"]

    def __init__(self, *args, **kwargs):
        self.target_hostname = kwargs.get("target_hostname")
        self.target_url = kwargs.get("target_url")
        self.scheme = kwargs.get("scheme")

        self.output_folder = kwargs.get("output_folder", f'{self._DEF_OUTPUT_DIRECTORY}')
        self._setup_results_path()

    def _setup_results_path(self):
        Path(self._get_results_directory()).mkdir(parents=True, exist_ok=True)  # recursively make directories
        full_path = os.path.join(self._get_results_directory(), self._get_results_filename())
        if os.path.isfile(full_path):
            os.remove(full_path)  # remove old files
        self._log(f"scan results will be saved in\t{full_path}")

    def _log(self, text):
        # TODO with colors based on type of message
        with ScanManager._LOGGER_MUTEX:
            print(f"[{self.target_hostname}] {(self.__class__.__name__ + ' ').ljust(20, '-')}> {text}")

    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        path = os.path.join(self.output_folder,
                            self.target_hostname.replace('.', '_'),
                            self.target_url.replace(f'{self.scheme}://', '').replace('.', '_'))

        return path

    def _get_results_filename(self, *args, **kwargs) -> str:
        return f"{self.__class__.__name__}.txt"

    def _save_results(self, results):
        path = os.path.join(self._get_results_directory(), self._get_results_filename())
        with open(path, "a") as res_file:
            res_file.write(f"{results}")


class Scanner(ScanManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.request_cooldown = kwargs.get("request_cooldown", ScannerDefaultParams.RequestCooldown)
        self.thread_count = kwargs.get("thread_count", ScannerDefaultParams.ThreadCount)
        self.request_timeout = kwargs.get("request_timeout", ScannerDefaultParams.RequestTimeout)

        self._default_headers = dict()  # for rotating user agents
        self._session: Union[requests.Session, None] = None
        self._setup_session()

        self._session_refresh_interval = kwargs.get("request_timeout", 1000)  # TODO
        self._session_refresh_count = 0

    def start_scanner(self) -> Any:
        try:
            self._log(f"starting scanner...")
            scan_results = self._start_scanner()
            self._log(f"scanner finished...")
            return scan_results
        except Exception as exc:
            self._log(f"aborting due to exception: {exc}")

    @abstractmethod
    def _start_scanner(self) -> Any:
        ...

    def _setup_session(self):
        if self.scheme not in self._ACCEPTED_SCHEMES:
            raise Exception(f"Missing / unsupported url scheme, should be one of: {', '.join(self._ACCEPTED_SCHEMES)}")
            # TODO exceptions class?

        if not self.target_url:
            raise Exception("Missing target url")  # TODO exceptions class?

        self._default_headers.clear()
        self._default_headers['User-Agent'] = get_random_useragent()  # TODO

        self._session = requests.Session()

    def _make_request(self, method: str, url: str, headers=None):
        if not self._session_refresh_count % self._session_refresh_interval:
            self._setup_session()
        if not headers:
            headers = dict()
        headers.update(self._default_headers)

        return self._session.request(method=method, url=url, headers=headers, timeout=self.request_timeout)

# ========= Default Scanner Params


class ExtendedEnum(Enum):
    def __get__(self, *args, **kwargs):
        """
        needed so we can access the values directly
        """
        return self.value


class ScannerDefaultParams(ExtendedEnum):
    RequestCooldown = 0.1
    ThreadCount = 4
    RequestTimeout = 1
    SuccessStatusCodes = [200, 301, 302]
    TooManyReqSleep = 10


if __name__ == "__main__":
    pass
