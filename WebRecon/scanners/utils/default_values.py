from enum import Enum


class _ExtendedEnum(Enum):
    def __get__(self, *args, **kwargs):
        """
        needed so we can access the values directly
        """
        return self.value if self.value else None

# ========= Default Scanner Params


class ScannerDefaultParams(_ExtendedEnum):
    ThreadCount = 4
    SuccessStatusCodes = [200, 301, 302]
    FileExtensions = []  # [".php", ".bak", ".orig", ".inc"]

# ========= Default Wordlist Paths


class WordlistDefaultPath(_ExtendedEnum):
    ContentScanner = "wordlists/test_webcontent_brute.txt"
    DNSScanner = "wordlists/test_subdomain_brute.txt"


# ========= Default Wordlist Paths

class NetworkDefaultParams(_ExtendedEnum):
    RequestCooldown = 0.1
    RequestTimeout = 1
    TooManyReqSleep = 10
