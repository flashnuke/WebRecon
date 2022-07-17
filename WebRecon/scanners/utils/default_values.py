from enum import Enum
from collections import defaultdict


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


class ScannerNames(_ExtendedEnum):
    DnsScan = "dns"
    ContentScan = "content"
    BypassScan = "403bypass"
    NmapScan = "nmap"


class NetworkDefaultParams(_ExtendedEnum):
    RequestCooldown = 0.1
    RequestTimeout = 1
    SessionRefreshInterval = 1000
    TooManyReqSleep = 10


class CacheDefaultParams(_ExtendedEnum):
    CacheMaxAge = 30 * 60
    ClearWhenFinished = True


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


class OutputColors(_ExtendedEnum):
    White = '\033[0m'
    Red = '\033[31m'
    Green = '\033[32m'
    Orange = '\033[33m'
    Blue = '\033[34m'
    Purple = '\033[35m'
    Cyan = '\033[36m'
    Gray = '\033[37m'
    Dim = '\033[2m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    # BLACK = "\033[0;30m"
    # RED = "\033[0;31m"
    # GREEN = "\033[0;32m"
    # BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    # PURPLE = "\033[0;35m"
    # CYAN = "\033[0;36m"
    # LIGHT_GRAY = "\033[0;37m"
    # DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    # BOLD = "\033[1m"
    FAINT = "\033[2m"
    # ITALIC = "\033[3m"
    # UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    # NEGATIVE = "\033[7m"
    # CROSSED = "\033[9m"
    # END = "\033[0m"


class OutputStatusKeys(_ExtendedEnum):
    State = "State"
    Progress = "Progress"  # todo method and print the iterated / amount numbers... maybe not every time to avoid overload
    Current = "Current"
    ResultsPath = "ResultsPath"
    Found = "Found"  # TODO rename
    Left = "Left"
    UsingCached = "UsingCached"


class OutputValues(_ExtendedEnum):
    StateSetup = ("setting up", OutputColors.Gray)
    StateRunning = ("running", OutputColors.Green)
    StateComplete = ("finished", OutputColors.Green)
    StateFail = ("failed", OutputColors.Red)  # TODO reason?

    BoolTrue = ("true", OutputColors.YELLOW)
    BoolFalse = "false"

    EmptyStatusVal = "---"
    ZeroStatusVal = "0"
    EmptyLine = ""


StatusKeyColorMap = {
    "Progress": OutputColors.Cyan,
    "Found": OutputColors.Blue
}

# TODO move elsewhere?

Banner = f"""
                         {OutputColors.Green}{OutputColors.BOLD} __        __{OutputColors.White}{OutputColors.YELLOW}   _    {OutputColors.White}{OutputColors.Green}{OutputColors.BOLD} ____ {OutputColors.White}{OutputColors.YELLOW}                     
                          {OutputColors.Green}{OutputColors.BOLD}\ \      / /{OutputColors.White}{OutputColors.YELLOW}__| |__ {OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}|  _ \{OutputColors.White}{OutputColors.YELLOW} ___  ___ ___  _ __  {OutputColors.White}                          
                           {OutputColors.Green}{OutputColors.BOLD}\ \ /\ / /{OutputColors.White}{OutputColors.YELLOW} _ \\ '_ \{OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}| |_){OutputColors.White}{OutputColors.YELLOW} / _ \/ __/ _ \| '_ \{OutputColors.White}                           
                            {OutputColors.Green}{OutputColors.BOLD}\ V  V /{OutputColors.White}{OutputColors.YELLOW}  __/ |_) {OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}|  _ <{OutputColors.White}{OutputColors.YELLOW}  __/ (_| (_) | | | |{OutputColors.White}                          
                             {OutputColors.Green}{OutputColors.BOLD}\_/\_/{OutputColors.White}{OutputColors.YELLOW} \___|_.__/{OutputColors.White}{OutputColors.Green}{OutputColors.BOLD}|_| \_\{OutputColors.White}{OutputColors.YELLOW}___|\___\___/|_| |_|{OutputColors.White}                          """
