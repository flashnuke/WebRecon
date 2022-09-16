import sys
import copy
import threading

from functools import lru_cache
from collections import deque
from typing import Union, Dict, Any
from .default_values import *
from .repo_banner import get_banner
from .exceptions.scanner_exceptions import MissingOutputDictKeys, InvalidOutputType

print = lambda *args, **kwargs: None  # to disable prints


class OutputManager(object):
    _INSTANCE = None
    _OUTPUT_CONT = dict()
    _OUTPUT_LEN = 0
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
                    raise MissingOutputDictKeys
                OutputManager._OUTPUT_CONT[output_type][source_name] = dict()
                for okey, oval in status_keys.items():
                    self.update_status(source_name, okey, oval, refresh_output=False)
                    OutputManager._OUTPUT_CONT[output_type][source_name][okey] = self.construct_status_val(okey, oval)
            elif output_type == OutputType.Lines:
                OutputManager._OUTPUT_CONT[OutputType.Lines][source_name] = deque(maxlen=OutputDefaultParams.MaxLen)
                for _ in range(OutputDefaultParams.MaxLen):
                    OutputManager._OUTPUT_CONT[OutputType.Lines][source_name].append(OutputDefaultParams.LinePrefix)
                OutputManager._OUTPUT_LEN += OutputDefaultParams.MaxLen + 1
            else:
                raise InvalidOutputType(output_type)
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
            status_color = getattr(OutputStatuskeyColor, output_key, OutputColors.White)

        valstr = f"{status_text}".rjust(OutputDefaultParams.LineWidth - len(output_key), " ")
        return f"{output_key}{status_color}{valstr}{OutputColors.White}"

    @staticmethod
    def is_key_in_status(source_name: str, output_key: str):
        with OutputManager._OUTPUT_MUTEX:
            return output_key in OutputManager._OUTPUT_CONT[OutputType.Status][source_name]

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
            OutputManager._OUTPUT_CONT[OutputType.Lines][source_name].appendleft(f"{OutputDefaultParams.LinePrefix} {line}")
            self._clear()
            self._flush()

    def _flush(self):
        for source, status_dict in OutputManager._OUTPUT_CONT[OutputType.Status].items():
            if source:
                sys.stdout.write(self._construct_output(OutputDefaultParams.Delimiter))
            sys.stdout.write(f"{OutputColors.BOLD}{self._construct_output(source)}{OutputColors.White}\n")
            for skey, sval in status_dict.items():
                sys.stdout.write(self._construct_output(f"{sval}"))
        for source, line_deq in OutputManager._OUTPUT_CONT[OutputType.Lines].items():
            sys.stdout.write(self._construct_output(OutputDefaultParams.Delimiter))
            sys.stdout.write(f"{OutputColors.BOLD}{self._construct_output(source)}{OutputColors.White}\n")
            for line in reversed(line_deq):
                sys.stdout.write(self._construct_output(line))
        sys.stdout.flush()

    def _clear(self):
        sys.stdout.write(self._construct_output(OutputManager._OUTPUT_LEN * OutputDefaultParams.LineRemove))

    @lru_cache(maxsize=50)
    def _construct_output(self, output: Any) -> str:
        return f"{output}\n"

    @staticmethod
    def print_banner():
        sys.stdout.write(get_banner())
