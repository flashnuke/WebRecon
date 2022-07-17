class ScannerException(Exception):
    _MESSAGE = ""

    def __init__(self, bad_input=""):
        message = self._generate_message(bad_input)
        super().__init__(message)

    def _generate_message(self, invalid_input) -> str:
        return f"{self._MESSAGE}: {invalid_input}" if invalid_input else self._MESSAGE


class InvalidScannerName(ScannerException):
    _MESSAGE = "Invalid scanner name"

    def __init__(self, scanner_name):
        super().__init__(scanner_name)


class UnsupportedScheme(ScannerException):
    _MESSAGE = "Unsupported or missing url scheme"

    def __init__(self, scheme_name):
        super().__init__(scheme_name)


class InvalidPath(ScannerException):
    _MESSAGE = "Failed to load path"

    def __init__(self, path_type, invalid_path):
        super().__init__(f"{path_type} -> {invalid_path}")


class InvalidOutputType(ScannerException):
    _MESSAGE = "Invalid output type"

    def __init__(self, output_type):
        super().__init__(output_type)


class MissingTargetURL(ScannerException):
    _MESSAGE = "Missing target url"

    def __init__(self):
        super().__init__()


class MissingOutputDictKeys(ScannerException):
    _MESSAGE = "Missing output dict keys"

    def __init__(self):
        super().__init__()
