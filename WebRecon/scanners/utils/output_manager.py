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
    _OUTPUT_CONT = dict()  # TODO to params
    _OUTPUT_LEN = 0

    def __new__(cls, *args, **kwargs):  # singleton
        if not isinstance(cls._INSTANCE, cls):
            cls._INSTANCE = object.__new__(cls)
            for output_type in OutputType:
                cls._OUTPUT_CONT[output_type.value] = dict()
        return cls._INSTANCE

    def __init__(self):
        pass

    @staticmethod
    def insert_output(source_name: str, output_type: OutputType, status_keys: Union[Dict[str, Any], None] = None):
        if source_name in OutputManager._OUTPUT_CONT[output_type]:
            return
        elif output_type == OutputType.Lines:
            OutputManager._OUTPUT_CONT[OutputType.Lines][source_name] = deque(maxlen=OutputManager._DEF_MAXLEN)
            for _ in range(OutputManager._DEF_MAXLEN):
                OutputManager._OUTPUT_CONT[OutputType.Lines][source_name].append('')
            OutputManager._OUTPUT_LEN += OutputManager._DEF_MAXLEN
        elif output_type == OutputType.Status:
            if not status_keys:
                raise Exception("missing keys for output dict")  # TODO exceptions
            OutputManager._OUTPUT_CONT[output_type][source_name] = deepcopy(status_keys)
            OutputManager._OUTPUT_LEN += len(status_keys)
        else:
            raise Exception(f"wrong output_type set: {output_type}")  # TODO exceptions
        OutputManager._OUTPUT_LEN += 2  # delimiter + source_name

    def remove_output(self, source_name: str, output_type: OutputType):
        if source_name in OutputManager._OUTPUT_CONT[output_type]:
            output_len = len(OutputManager._OUTPUT_CONT[output_type][source_name])
            OutputManager._OUTPUT_CONT[output_type].pop(source_name)
            self._clear()
            OutputManager._OUTPUT_LEN = OutputManager._OUTPUT_LEN - output_len
            self._flush()

    def update_status(self, source_name: str, output_key: str, output_val: Any):
        # TODO add lock here (or to all methods??)

        OutputManager._OUTPUT_CONT[OutputType.Status][source_name][output_key] = output_val
        self._clear()
        self._flush()

    def update_lines(self, source_name: str, line: str):
        # TODO add lock here (or to all methods??)

        OutputManager._OUTPUT_CONT[OutputType.Lines][source_name].append(line)
        self._clear()
        self._flush()

    @staticmethod
    def _flush():
        for source, status_dict in OutputManager._OUTPUT_CONT[OutputType.Status].items(): # TODO if initial dont remove
            print(OutputManager._DELIMITER)
            print(source)
            for skey, sval in status_dict.items():
                print(f"{skey} -> {sval}")
        for source, line_deq in OutputManager._OUTPUT_CONT[OutputType.Lines].items():  # TODO if initial dont remove
            print(OutputManager._DELIMITER)
            print(source)
            for line in line_deq:
                print(line)

    @staticmethod
    def _clear():
        print(OutputManager._OUTPUT_LEN * OutputManager._LINE_REMOVE)


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
