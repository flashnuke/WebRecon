from collections import defaultdict, deque
from copy import deepcopy
from typing import Union, Dict, Any


class OutputManager:
    # TODO suppress all other output from other libraries to avoid messing up
    # TODO make singleton
    _DEF_MAXLEN = 3  # TODO make sure to initialize with this size
    _LINE_REMOVE = "\x1b[1A\x1b[2K" # TODO rename
    _DELIMITER = "================================================" # TODO ?
    _STATUS_OUTPUT = dict()  # TODO to params
    _LINES_OUTPUT = dict()  # TODO to params
    _OUTPUT_LEN = 0

    def __init__(self, source_name: str, output_type: str, status_keys: Union[Dict[str, Any], None] = None):
        if source_name in OutputManager._STATUS_OUTPUT or source_name in OutputManager._LINES_OUTPUT:
            return
        elif output_type == "lines":
            OutputManager._LINES_OUTPUT[source_name] = deque(maxlen=OutputManager._DEF_MAXLEN)
            for _ in range(OutputManager._DEF_MAXLEN):
                OutputManager._LINES_OUTPUT[source_name].append('')
            OutputManager._OUTPUT_LEN += OutputManager._DEF_MAXLEN
        elif output_type == "status":
            if not status_keys:
                raise Exception("missing keys for output dict")  # TODO excpetions
            OutputManager._STATUS_OUTPUT[source_name] = deepcopy(status_keys)
            OutputManager._OUTPUT_LEN += len(status_keys)
        else:
            raise Exception(f"wrong output_type set: {output_type}")  # TODO excpetions
        OutputManager._OUTPUT_LEN += 1  # delimiter

    def update_status(self, source_name, output_key, output_val):
        # TODO add lock here

        OutputManager._STATUS_OUTPUT[source_name][output_key] = output_val
        self._flush()

    def update_lines(self, source_name, line):
        # TODO add lock here

        OutputManager._LINES_OUTPUT[source_name].append(line)
        self._flush()

    def _flush(self):
        print(OutputManager._OUTPUT_LEN * OutputManager._LINE_REMOVE)
        for source, status_dict in OutputManager._STATUS_OUTPUT.items(): # TODO if initial dont remove
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
