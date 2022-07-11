import copy
import sys
import threading

import requests
import os
import queue
import time
import json
import urllib3

from typing import Any, Dict, Union
from pathlib import Path
from functools import lru_cache
from abc import abstractmethod
from .utils import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    _DEF_CACHE_DIRECTORY = os.path.join("scanners/utils/.cache_scan")  # TODO all this to another file
    _DEF_OUTPUT_DIRECTORY = "results"
    _ACCEPTED_SCHEMES = ["http", "https"]
    _ERROR_LOG_NAME = f"{OutputColors.Red}error_log{OutputColors.White}"  # TODO to default values?
    _SCAN_COLOR = OutputColors.White
    _SUPPORTS_CACHE = False  # overwrite for each scanner
    _CACHE_MUTEX = threading.RLock()

    def __init__(self, scheme, target_hostname, target_url, *args, **kwargs):
        self.target_hostname = target_hostname
        self.target_url = target_url
        self.scheme = scheme

        self.wordlist_path = kwargs.get("wordlist_path", getattr(WordlistDefaultPath, self.__class__.__name__, None))  # TODO argparse

        self.results_path = kwargs.get("results_path", f'{self._DEF_OUTPUT_DIRECTORY}')
        self.results_path_full = self._setup_results_path()

        self._use_prev_cache = False
        self._cache_dict: dict = self._load_cache_if_exists()  # TODO if finished - remove cache
        if not self._use_prev_cache:
            self._remove_old_results()

        self._current_progress_perc = int()
        self._output_manager = None
        self._output_manager_setup()

    def _output_manager_setup(self):
        self._output_manager = OutputManager()
        keys = self._define_status_output()
        if keys:
            self._output_manager.insert_output(self._get_scanner_name(), OutputType.Status, keys)
        self._output_manager.insert_output(self._ERROR_LOG_NAME, OutputType.Lines)

    @lru_cache()
    def _get_scanner_name(self, include_ansi=True) -> str:
        return f"{self.__class__._SCAN_COLOR if include_ansi else ''}{self.__class__.__name__}"

    def _setup_results_path(self) -> str:
        Path(self._get_results_directory()).mkdir(parents=True, exist_ok=True)  # recursively make directories
        full_path = self._get_results_fullpath()
        return full_path

    def _log_line(self, log_name, line: str):
        self._output_manager.update_lines(log_name, line)

    def _log_status(self, lkey: str, lval: Any):
        self._output_manager.update_status(self._get_scanner_name(), lkey, lval)

    def _log_exception(self, exc_text, abort: bool):
        self._log_line(self._ERROR_LOG_NAME, f" {self.__class__.__name__} exception - {exc_text}, aborting - {abort}")

    def _save_results(self, results: str, mode="a"):
        with ScanManager._CACHE_MUTEX:
            path = self._get_results_fullpath()
            with open(path, mode) as res_file:
                res_file.write(f"{results}")
            self._update_cache_results()

    def _update_cache_results(self):
        if self._supports_cache:
            with ScanManager._CACHE_MUTEX:
                self._cache_dict["results_filehash"] = get_filehash(self._get_results_fullpath())
                with open(self._get_cache_fullpath(), "r") as cf:
                    cache_json = json.load(cf)
                cache_json["scanners"][self._get_scanner_name(include_ansi=False)] = self._cache_dict
                with open(self._get_cache_fullpath(), "w") as cf:
                    json.dump(cache_json, cf)  # todo json in req.txt needed?


                    # TODO if bad cache then ignore cache

    def _load_cache_if_exists(self) -> dict:
        if self._supports_cache:
            with ScanManager._CACHE_MUTEX:
                cache_path = Path(self._get_cache_fullpath())
                if cache_path.exists():
                    with cache_path.open('r') as cf:
                        cache_json = json.load(cf)
                        scan_cache = cache_json["scanners"].get(self._get_scanner_name(include_ansi=False))
                        if scan_cache:
                            results_filehash = scan_cache.get("results_filehash", "")
                            wordlist_filehash = scan_cache.get("wordlist_filehash", "")
                            if results_filehash == get_filehash(self._get_results_fullpath()) and \
                                    wordlist_filehash == get_filehash(os.path.join(self.wordlist_path)) and \
                                    time.time() - scan_cache.get("timestamp", 0) < 22222:  # todo proper time limit
                                self._use_prev_cache = True
                                return scan_cache
                else:  # create file
                    with open(cache_path, mode='w') as cf:
                        json.dump(self._init_cache_file_dict(self.target_url), cf)
        return self._init_cache_scanner_dict()

    def _remove_old_results(self):
        if os.path.isfile(self.results_path_full):
            os.remove(self.results_path_full)

    def _supports_cache(self) -> bool:
        return self.__class__._SUPPORTS_CACHE

    def _get_results_filename(self) -> str:
        return f"{self.__class__.__name__}.txt"

    def _get_cache_filename(self) -> str:
        return f"cache_{self._format_name_for_path(self.target_hostname)}.json"

    @staticmethod
    def _init_cache_file_dict(target_url: str) -> dict:
        return {
            "target_url": target_url,
            "scanners": dict()
        }

    def _init_cache_scanner_dict(self) -> dict:
        return {
            "wordlist_filehash": get_filehash(self.wordlist_path),
            "results_filehash": "",
            "finished": 0,
            "timestamp": time.time()
        }

    @lru_cache
    def _get_results_directory(self, *args, **kwargs) -> str:
        path = os.path.join(self.results_path,
                            self._format_name_for_path(self.target_hostname),
                            self._format_name_for_path(self.target_url))

        return path

    @lru_cache
    def _get_cache_directory(self) -> str:
        return self._DEF_CACHE_DIRECTORY

    def _get_results_fullpath(self) -> str:
        return os.path.join(self._get_results_directory(), self._get_results_filename())

    def _get_cache_fullpath(self) -> str:
        return os.path.join(self._get_cache_directory(), self._get_cache_filename())

    @abstractmethod
    def _define_status_output(self) -> Dict[str, Any]:
        ...

    @lru_cache(maxsize=5)
    def generate_url_base_path(self, dnsname: str) -> str:
        return f"{self.scheme}://{dnsname}.{self.target_hostname}"

    @lru_cache(maxsize=5)
    def _format_name_for_path(self, name: str) -> str:
        return name.replace(f'{self.scheme}://', '').replace('.', '_')

    def _update_progress_status(self, finished_c, total_c):
        progress = (100 * finished_c) // total_c
        self._log_status(OutputStatusKeys.Left, f"{total_c - finished_c} out of {total_c}")

        if progress % ScannerDefaultParams.ProgBarIntvl == 0 and progress > self._current_progress_perc:
            print_prog_mod = 5  # TODO params
            print_prog_count = progress // print_prog_mod  # TODO params
            print_prog_max = (100 // print_prog_mod)  # TODO params
            prog_str = f"[{('#' * print_prog_count).ljust(print_prog_max - print_prog_count, '-')}]"
            self._log_status(OutputStatusKeys.Progress, prog_str)
            self._current_progress_perc = progress
            with ScanManager._CACHE_MUTEX:
                self._cache_dict["finished"] = finished_c


class Scanner(ScanManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.wordlist_path:
            self.words_queue: queue.Queue = self.load_words()

        self.request_cooldown = kwargs.get("request_cooldown", NetworkDefaultParams.RequestCooldown)
        self.thread_count = kwargs.get("thread_count", ScannerDefaultParams.ThreadCount)
        self.request_timeout = kwargs.get("request_timeout", NetworkDefaultParams.RequestTimeout)

        self._default_headers = dict()  # for rotating user agents
        self._session: Union[requests.Session, None] = None
        self._setup_session()

        self._session_refresh_interval = kwargs.get("session_refresh_interval",
                                                    NetworkDefaultParams.SessionRefreshInterval)
        self._session_refresh_count = 0

    def load_words(self) -> queue.Queue:
        start_idx = self._cache_dict.get("finished", 0)
        with open(self.wordlist_path, 'r') as wl:
            words = queue.Queue()
            for word in wl.readlines()[start_idx:]:
                words.put(word.rstrip("\n"))
        return words

    def start_scanner(self) -> Any:
        try:
            self._log_status(OutputStatusKeys.State, OutputValues.StateSetup)
            scan_results = self._start_scanner()
            self._log_status(OutputStatusKeys.State, OutputValues.StateComplete)
            return scan_results
        except Exception as exc:
            self._log_exception(exc, True)  # TODO try to have our own exceptions

    @abstractmethod
    def _start_scanner(self) -> Any:
        ...

    @abstractmethod
    def _define_status_output(self) -> Dict[str, Any]:
        ...

    def _setup_session(self):
        if self.scheme not in self._ACCEPTED_SCHEMES:
            raise Exception(f"Missing / unsupported url scheme, should be one of: {', '.join(self._ACCEPTED_SCHEMES)}")
            # TODO exceptions class?

        if not self.target_url:
            raise Exception("Missing target url")  # TODO exceptions class?

        self._default_headers.clear()
        self._default_headers['User-Agent'] = get_random_useragent()

        self._session = requests.Session()

    def _make_request(self, method: str, url: str, headers=None, **kwargs):
        if not self._session_refresh_count % self._session_refresh_interval:
            self._setup_session()
        if not headers:
            headers = dict()
        headers.update(self._default_headers)

        res = self._session.request(method=method, url=url, headers=headers, timeout=self.request_timeout, **kwargs)

        if res.status_code == 429:  # to default values?
            time.sleep(NetworkDefaultParams.TooManyReqSleep)

        return res


if __name__ == "__main__":
    pass
