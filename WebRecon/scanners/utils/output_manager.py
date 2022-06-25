from collections import defaultdict, deque
from copy import deepcopy
from typing import Union, Dict, Any
from .default_values import OutputType


class OutputManager(object):
    # TODO suppress all other output from other libraries to avoid messing up
    # TODO make singleton
    _INSTANCE = None
    _DEF_MAXLEN = 3  # TODO make sure to initialize with this size
    _LINE_REMOVE = "\x1b[1A\x1b[2K" # TODO rename
    _DELIMITER = "================================================" # TODO ?
    _STATUS_OUTPUT = dict()  # TODO to params
    _LINES_OUTPUT = dict()  # TODO to params
    _OUTPUT_LEN = 0

    def __new__(cls, *args, **kwargs):  # singleton
        if not isinstance(cls._INSTANCE, cls):
            cls._INSTANCE = object.__new__(cls)
        return cls._INSTANCE

    def __init__(self):
        pass

    @staticmethod
    def set_new_output(source_name: str, output_type: OutputType, status_keys: Union[Dict[str, Any], None] = None):
        if source_name in OutputManager._STATUS_OUTPUT or source_name in OutputManager._LINES_OUTPUT:
            return
        elif output_type == OutputType.Lines:
            OutputManager._LINES_OUTPUT[source_name] = deque(maxlen=OutputManager._DEF_MAXLEN)
            for _ in range(OutputManager._DEF_MAXLEN):
                OutputManager._LINES_OUTPUT[source_name].append('')
            OutputManager._OUTPUT_LEN += OutputManager._DEF_MAXLEN
        elif output_type == OutputType.Status:
            if not status_keys:
                raise Exception("missing keys for output dict")  # TODO excpetions
            OutputManager._STATUS_OUTPUT[source_name] = deepcopy(status_keys)
            OutputManager._OUTPUT_LEN += len(status_keys)
        else:
            raise Exception(f"wrong output_type set: {output_type}")  # TODO excpetions
        OutputManager._OUTPUT_LEN += 2  # delimiter + source_name

    def update_status(self, source_name: str, output_key: str, output_val: Any):
        # TODO add lock here

        OutputManager._STATUS_OUTPUT[source_name][output_key] = output_val
        self._flush()

    def update_lines(self, source_name: str, line: str):
        # TODO add lock here

        OutputManager._LINES_OUTPUT[source_name].append(line)
        self._flush()

    @staticmethod
    def _flush():
        print(OutputManager._OUTPUT_LEN * OutputManager._LINE_REMOVE)
        for source, status_dict in OutputManager._STATUS_OUTPUT.items(): # TODO if initial dont remove
            print(OutputManager._DELIMITER)
            print(source)
            for skey, sval in status_dict.items():
                print(f"{skey} -> {sval}")

# TODO _log_excpetion and _log_status
#
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
