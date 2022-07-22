import os

from enum import Enum
from .common_ports import get_common_ports


class _ExtendedEnum(Enum):
    def __get__(self, *args, **kwargs):
        """
        needed so we can access the values directly
        """
        return self.value if self.value else None

# ========= OutputManager Settings




class OutputType(_ExtendedEnum):
    Lines = "lines"
    Status = "status"


class OutputColors(_ExtendedEnum):
    White = '\033[0m'
    Red = '\033[31m'
    Green = '\033[32m'
    Orange = '\033[33m'
    YELLOW = "\033[1;33m"
    Blue = '\033[34m'
    Purple = '\033[35m'
    Cyan = '\033[36m'
    Gray = '\033[37m'
    Dim = '\033[2m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLUE = "\033[0;34m"
    FAINT = "\033[2m"
    BLINK = "\033[5m"


class OutputDefaultParams(_ExtendedEnum):
    LineRemove = "\x1b[1A\x1b[2K"
    LineWidth = 150
    MaxLen = 5
    Delimiter = f"{OutputColors.Purple}{LineWidth * '='}{OutputColors.White}"
    LinePrefix = f"{OutputColors.Gray}>{OutputColors.White}"


class OutputStatusKeys(_ExtendedEnum):
    State = "State"
    Progress = "Progress"
    Current = "Current"
    ResultsPath = "ResultsPath"
    Found = "Found"
    Left = "Left"
    UsingCached = "UsingCached"


class OutputValues(_ExtendedEnum):
    StateSetup = ("setting up", OutputColors.Gray)
    StateRunning = ("running", OutputColors.Green)
    StateComplete = ("finished", OutputColors.Green)
    StateFail = ("failed", OutputColors.Red)

    BoolTrue = ("true", OutputColors.YELLOW)
    BoolFalse = "false"

    EmptyStatusVal = "---"
    ZeroStatusVal = "0"
    EmptyLine = ""


class OutputStatuskeyColor(_ExtendedEnum):
    Progress = OutputColors.Cyan
    Found = OutputColors.Blue


# ========= Default Scanner Params


class ScannerNames(_ExtendedEnum):
    DnsScan = "dns"
    ContentScan = "content"
    BypassScan = "403bypass"
    NmapScan = "nmap"


class ScannerDefaultParams(_ExtendedEnum):
    AcceptedSchemes = ["http", "https"]
    DefaultCacheDirectory = os.path.join("scanners/cache_scan")
    DefaultSubdomain = "www"
    ErrorLogName = f"{OutputColors.Red}error_log{OutputColors.White}"
    FileExtensions = []  # i.e: [".php", ".bak", ".orig", ".inc"]
    ForbiddenSCode = 403
    SuccessStatusCodes = [200, 301, 302]
    ThreadCount = 4


class ScannerProgBarParams(_ExtendedEnum):
    ProgBarIntvl = 1
    ProgressMod = 3
    ProgressMax = (100 // ProgressMod)


class WordlistDefaultPath(_ExtendedEnum):
    ContentScanner = "wordlists/test_webcontent_brute.txt"
    DNSScanner = "wordlists/test_subdomain_brute.txt"


class NetworkDefaultParams(_ExtendedEnum):
    RequestCooldown = 0.1
    RequestTimeout = 1
    SessionRefreshInterval = 1000
    TooManyReqSleep = 10


class CacheDefaultParams(_ExtendedEnum):
    CacheMaxAge = 30 * 60
    ClearWhenFinished = True

# ========= Default ArgParser Params


class ArgParserDefaultParams(_ExtendedEnum):
    NmapCmdlineargs = "-sV -sU -sS"
    NmapPorts = get_common_ports()

    DNSDefaultWL = os.path.join(os.getcwd(), WordlistDefaultPath.DNSScanner)
    ContentDefaultWL = os.path.join(os.getcwd(), WordlistDefaultPath.ContentScanner)
    ResultsDefaultPath = os.path.join(os.getcwd(), "results")

    LeftPad = 2 * " "
    LJustWidth = 22


class ArgParserArgName(_ExtendedEnum):
    NmapCmdlineargs = f'cmdline_args_{ScannerNames.NmapScan}'
    NmapPorts = f'ports_{ScannerNames.NmapScan}'


# ========= Default PPrint Params

class PPrintDefaultParams(_ExtendedEnum):
    Compact = False
    Width = 200

