from enum import Enum


class _ExtendedEnum(Enum):
    def __get__(self, *args, **kwargs):
        """
        needed so we can access the values directly
        """
        return self.value if self.value else None

# ========= Default Scanner Generic Params


class ScannerDefaultParams(_ExtendedEnum):
    DefaultSubdomain = "www"
    FileExtensions = []  # [".php", ".bak", ".orig", ".inc"]
    SuccessStatusCodes = [200, 301, 302]
    ThreadCount = 4
    ProgBarIntvl = 1


class NetworkDefaultParams(_ExtendedEnum):
    RequestCooldown = 0.1
    RequestTimeout = 1
    SessionRefreshInterval = 1000
    TooManyReqSleep = 10


# ========= Default Wordlist Paths


class WordlistDefaultPath(_ExtendedEnum):
    ContentScanner = "wordlists/test_webcontent_brute.txt"
    DNSScanner = "wordlists/test_subdomain_brute.txt"


# ========= Default PPrint Params

class PPrintDefaultParams(_ExtendedEnum):
    Compact = False
    Width = 200

# ========= OutputManager Settings


class OutputType(_ExtendedEnum):
    Lines = "lines"
    Status = "status"


class OutputStatusKeys(_ExtendedEnum):
    State = "State"
    Progress = "Progress"  # todo method and print the iterated / amount numbers... maybe not every time to avoid overload
    Current = "Current"
    ResultsPath = "ResultsPath"
    Found = "Found"  # TODO rename
    Left = "Left"


class OutputValues(_ExtendedEnum):
    StateSetup = "setting up"
    StateRunning = "running"
    StateComplete = "finished"
    StateFail = "failed"  # TODO reason?

    EmptyStatusVal = "---"
    ZeroStatusVal = 0
    EmptyLine = ""

