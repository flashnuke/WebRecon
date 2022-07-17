class WebscannerException(Exception):
    _MESSAGE = ""

    def __init__(self, bad_input=""):
        message = self._generate_message(bad_input)
        super().__init__(message)

    def _generate_message(self, invalid_input) -> str:
        return f"{self._MESSAGE}: {invalid_input}" if invalid_input else self._MESSAGE

# ====== Scanner Exceptions


class InvalidScannerName(WebscannerException):
    _MESSAGE = "Invalid scanner name"

    def __init__(self, scanner_name):
        super().__init__(scanner_name)


class UnsupportedScheme(WebscannerException):
    _MESSAGE = "Unsupported or missing url scheme"

    def __init__(self, scheme_name):
        super().__init__(scheme_name)


class InvalidPathLoad(WebscannerException):
    _MESSAGE = "Failed to load path"

    def __init__(self, path_type, invalid_path):
        super().__init__(f"{path_type} -> {invalid_path}")


class MissingTargetURL(WebscannerException):
    _MESSAGE = "Missing target url"

    def __init__(self):
        super().__init__()


# ====== OutputManager Exceptions


class InvalidOutputType(WebscannerException):
    _MESSAGE = "Invalid output type"

    def __init__(self, output_type):
        super().__init__(output_type)


class MissingOutputDictKeys(WebscannerException):
    _MESSAGE = "Missing output dict keys"

    def __init__(self):
        super().__init__()

# ====== Parser Exceptions


class ContradictingArguments(WebscannerException):
    _MESSAGE = "The chosen arguments cannot be set simultaneously"

    def __init__(self, args: list[str]):
        super().__init__(','.join(args))


class MissingArguments(WebscannerException):
    _MESSAGE = "Missing arguments"

    def __init__(self, args: list[str]):
        super().__init__(','.join(args))

