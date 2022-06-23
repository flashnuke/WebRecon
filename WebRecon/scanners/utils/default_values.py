from enum import Enum


class _ExtendedEnum(Enum):
    def __get__(self, *args, **kwargs):
        """
        needed so we can access the values directly
        """
        return self.value if self.value else None

# ========= Default Scanner Params


class ScannerDefaultParams(_ExtendedEnum):
    DefaultSubdomain = "www"
    FileExtensions = []  # [".php", ".bak", ".orig", ".inc"]
    SuccessStatusCodes = [200, 301, 302]
    ThreadCount = 4


class NetworkDefaultParams(_ExtendedEnum):
    RequestCooldown = 0.1
    RequestTimeout = 1
    SessionRefreshInterval = 1000
    TooManyReqSleep = 10

# ========= Default Wordlist Paths


class WordlistDefaultPath(_ExtendedEnum):
    ContentScanner = "wordlists/test_webcontent_brute.txt"
    DNSScanner = "wordlists/test_subdomain_brute.txt"


# ========= Misc Wordlist Paths

class PPrintDefaultParams(_ExtendedEnum):
    Compact = False
    Width = 200
