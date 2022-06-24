from collections import defaultdict, deque


class OutputManager:
    # TODO suppress all other output from other libraries to avoid messing up
    # TODO make singleton
    _DEF_MAXLEN = 3  # TODO make sure to initialize with this size
    _LINE_REMOVE = "\x1b[1A\x1b[2K" # TODO rename
    _OUTPUT_MAPPER = dict()  # TODO to params

    def __init__(self, scanner_name):
        OutputManager._OUTPUT_MAPPER[scanner_name] = deque(maxlen=OutputManager._DEF_MAXLEN)
        for _ in range(OutputManager._DEF_MAXLEN):
            OutputManager._OUTPUT_MAPPER[scanner_name].append('')

    @staticmethod
    def print_output(source, output):
        for line in output.split("\n"):  # TODO make sure we dont get a big one... print separately
            OutputManager._OUTPUT_MAPPER[source].append(line)
        print(2 * OutputManager._LINE_REMOVE * len(OutputManager._OUTPUT_MAPPER) * OutputManager._DEF_MAXLEN)
        for source, output_deq in OutputManager._OUTPUT_MAPPER.items(): # TODO if initial dont remove
            for line in output_deq:
                print(f"{source} -> {line}")
            print("=====")