import copy
import threading
from collections import defaultdict, deque
from copy import deepcopy
from typing import Union, Dict, Any
from .default_values import OutputType, OutputColors, StatusKeyColorMap, Banner
from functools import lru_cache
import sys

print = lambda *args, **kwargs: None  # to disable prints


class OutputManager(object):
    _INSTANCE = None
    _DEF_MAXLEN = 5
    _LINE_REMOVE = "\x1b[1A\x1b[2K" # TODO rename
    _OUTPUT_CONT = dict()  # TODO to params
    _OUTPUT_LEN = 0
    _LINE_WIDTH = 100
    _DELIMITER = f"{OutputColors.Purple}{_LINE_WIDTH * '='}{OutputColors.White}"
    _LINE_PREF = f"{OutputColors.Gray}>{OutputColors.White}"
    _OUTPUT_MUTEX = threading.RLock()

    def __new__(cls, *args, **kwargs):  # singleton
        if not isinstance(cls._INSTANCE, cls):
            cls._INSTANCE = object.__new__(cls)
            for output_type in OutputType:
                cls._OUTPUT_CONT[output_type.value] = dict()
            cls.print_banner()
        return cls._INSTANCE

    def __init__(self):
        pass

    def insert_output(self, source_name: str, output_type: OutputType, status_keys: Union[Dict[str, Any], None] = None):
        if source_name in OutputManager._OUTPUT_CONT[output_type]:
            return
        with OutputManager._OUTPUT_MUTEX:
            self._clear()
            if output_type == OutputType.Status:
                if not status_keys:
                    raise Exception("missing keys for output dict")  # TODO exceptions
                OutputManager._OUTPUT_CONT[output_type][source_name] = dict()
                for okey, oval in status_keys.items():
                    self.update_status(source_name, okey, oval, refresh_output=False)
                    OutputManager._OUTPUT_CONT[output_type][source_name][okey] = self.construct_status_val(okey, oval)
            elif output_type == OutputType.Lines:
                OutputManager._OUTPUT_CONT[OutputType.Lines][source_name] = deque(maxlen=OutputManager._DEF_MAXLEN)
                for _ in range(OutputManager._DEF_MAXLEN):
                    OutputManager._OUTPUT_CONT[OutputType.Lines][source_name].append(OutputManager._LINE_PREF)
                # appended_output_lines += OutputManager._DEF_MAXLEN
                OutputManager._OUTPUT_LEN += OutputManager._DEF_MAXLEN + 1
            else:
                raise Exception(f"wrong output_type set: {output_type}")  # TODO exceptions
            OutputManager._OUTPUT_LEN += 3 if source_name else 2  # delimiter + source_name (if exists)
            self._flush()

    def remove_output(self, source_name: str, output_type: OutputType):
        with OutputManager._OUTPUT_MUTEX:
            if source_name in OutputManager._OUTPUT_CONT[output_type]:
                output_len = len(OutputManager._OUTPUT_CONT[output_type][source_name])
                OutputManager._OUTPUT_CONT[output_type].pop(source_name)
                self._clear()
                OutputManager._OUTPUT_LEN = OutputManager._OUTPUT_LEN - output_len
                self._flush()

    @staticmethod
    def construct_status_val(output_key, output_val):
        if isinstance(output_val, tuple):
            status_text, status_color = output_val
        else:
            status_text = output_val
            status_color = StatusKeyColorMap.get(output_key, OutputColors.White)  # TODO cache or smth

        valstr = f"{status_text}".rjust(OutputManager._LINE_WIDTH - len(output_key), " ")
        return f"{output_key}{status_color}{valstr}{OutputColors.White}"

    def update_status(self, source_name: str, output_key: str, output_val: Any, refresh_output=True):
        with OutputManager._OUTPUT_MUTEX:
            if output_key not in OutputManager._OUTPUT_CONT[OutputType.Status][source_name]:
                OutputManager._OUTPUT_LEN += 1
            OutputManager._OUTPUT_CONT[OutputType.Status][source_name][output_key] = self.construct_status_val(output_key, output_val)
            if refresh_output:
                self._clear()
                self._flush()

    def update_lines(self, source_name: str, line: str):
        with OutputManager._OUTPUT_MUTEX:
            OutputManager._OUTPUT_CONT[OutputType.Lines][source_name].appendleft(f"{OutputManager._LINE_PREF} {line}")
            self._clear()
            self._flush()

    def _flush(self):
        for source, status_dict in OutputManager._OUTPUT_CONT[OutputType.Status].items():  # TODO if initial dont remove
            if source:
                sys.stdout.write(self._construct_output(self._DELIMITER))
            sys.stdout.write(f"{OutputColors.BOLD}{self._construct_output(source)}{OutputColors.White}\n")  # TODO sys write with construct to another method
            for skey, sval in status_dict.items():
                sys.stdout.write(self._construct_output(f"{sval}"))
        for source, line_deq in OutputManager._OUTPUT_CONT[OutputType.Lines].items():  # TODO if initial dont remove
            sys.stdout.write(self._construct_output(self._DELIMITER))
            sys.stdout.write(f"{OutputColors.BOLD}{self._construct_output(source)}{OutputColors.White}\n")
            for line in line_deq:
                sys.stdout.write(self._construct_output(line))
        sys.stdout.flush()

    def _clear(self):
        sys.stdout.write(self._construct_output(OutputManager._OUTPUT_LEN * OutputManager._LINE_REMOVE))

    @lru_cache(maxsize=50)
    def _construct_output(self, output: Any) -> str:
        return f"{output}\n"

    @staticmethod
    def print_banner():
        sys.stdout.write(Banner)

    @staticmethod
    def get_status_dict(source_name: str, output_type: OutputType):
        """
        a getter to be used from OUTSIDE the class ONLY (to avoid deadlocks)
        """
        with OutputManager._OUTPUT_MUTEX:
            return copy.deepcopy(OutputManager._OUTPUT_CONT[output_type][source_name])

# TODO compatible with linux only OR ELSE bail out
# TODO no exception is ok... unless handled (due to output limitations)

# WebRecon
# Host:
# status:
# current_target:
# total_left
# percentage_bar?
# results_path
#
#
# content_scan
# status:
# current_w:
# found:
# percentage_bar
# results_path
#
# bypass
# status:
# last_w:
# total_found:
# results_path
#
# nmap
# status
# results_path
#
# exception_log
