import argparse

from .default_values import *
from .exceptions.scanner_exceptions import ContradictingArguments, MissingArguments


def get_argument_parser() -> argparse.ArgumentParser:
    # Create the parser and add arguments
    parser = argparse.ArgumentParser(description=f'description:\n{ArgParserDefaultParams.LeftPad}'
                                                 f'a variety of pentest tools for scanning vulnerabilities'
                                                 f' on a given host',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     usage=f""
                                           f"\n{ArgParserDefaultParams.LeftPad}"
                                           f"{'WebRecon -sA'.ljust(ArgParserDefaultParams.LJustWidth)}run all scans (default)"
                                           f"\n{ArgParserDefaultParams.LeftPad}"
                                           f"{'WebRecon -sC *scans'.ljust(ArgParserDefaultParams.LJustWidth)}"
                                           f"run custom scans (i.e: `WebRecon -sC dns content`)",
                                     epilog="Types of scans:\n"
                                            f"{ArgParserDefaultParams.LeftPad}"
                                            f"* {ScannerNames.DnsScan} -> a recursive multi-threaded scan for subdomains\n"
                                            f"{ArgParserDefaultParams.LeftPad}"
                                            f"* {ScannerNames.ContentScan} -> a multi-threaded content scan for vulnerable pages\n"
                                            f"{ArgParserDefaultParams.LeftPad}"
                                            f"* {ScannerNames.BypassScan} -> perform attempts to bypass a 403 page "
                                            f"(requires scan: {ScannerNames.ContentScan})\n"
                                            f"{ArgParserDefaultParams.LeftPad}"
                                            f"* {ScannerNames.NmapScan} -> an nmap port scan")
    parser.add_argument(dest='target_url', type=str, help="The target host url")

    parser.add_argument("-sA", "--scan-all", dest='scan_all', action='store_true',
                        help="perform all scans")
    parser.add_argument("-sC", "--scan-custom", dest='scan_custom', action="store", nargs="+", metavar=("", "s1, s2"),
                        type=str, help="custom scans (case-sensitive)")

    parser.add_argument("-c", "--cache", dest='disable_cache', action="store_false",
                        default=True, help="enable cache (disabled by default)")

    parser.add_argument("-e", f"--set-{ScannerNames.ContentScan}scan-ext", dest='extensions', action="store",
                        default=str(), metavar="ext1,ext2",
                        help='test various file extensions for each attempt in the wordlist (example: "php,bak,html")')

    parser.add_argument(f"--set-{ScannerNames.DnsScan}scan-wl", dest=f'wl_{ScannerNames.DnsScan}', action='store',
                        metavar="PATH_TO_WORDLIST",
                        type=str, default=ArgParserDefaultParams.DNSDefaultWL,
                        help=f"path to the dns scan wordlist"
                             f" (default: {ArgParserDefaultParams.DNSDefaultWL})")

    parser.add_argument(f"--set-{ScannerNames.ContentScan}scan-wl", action='store',
                        dest=f'wl_{ScannerNames.ContentScan}', metavar="PATH_TO_WORDLIST",
                        type=str, default=ArgParserDefaultParams.ContentDefaultWL,
                        help=f"path to the content scan wordlist"
                             f" (default: {ArgParserDefaultParams.ContentDefaultWL})")

    parser.add_argument("--set-results-directory", dest='results_path', metavar="PATH_TO_DIRECTORY",
                        type=str, default=ArgParserDefaultParams.ResultsDefaultPath,
                        help=f"path to the main results directory"
                             f" (default: {ArgParserDefaultParams.ResultsDefaultPath})")

    parser.add_argument(f"--set-{ScannerNames.NmapScan}scan-cmdline_args", action='store',
                        dest=ArgParserArgName.NmapCmdlineargs, metavar="CMDLINE_ARGS",
                        type=str, default=ArgParserDefaultParams.NmapCmdlineargs,
                        help=f"cmdline arguments to be passed into the nmap scan"
                             f" (default: {ArgParserDefaultParams.NmapCmdlineargs})")

    parser.add_argument(f"--set-{ScannerNames.NmapScan}scan-ports", action='store',
                        dest=ArgParserArgName.NmapPorts, metavar="PORTS",
                        type=str, default=ArgParserDefaultParams.NmapPorts,
                        help=f"ports to be scanned by the nmap scanner"
                             f" (default: {len(ArgParserDefaultParams.NmapPorts)} common ports)")

    return parser


def parse_scan_list(arguments: argparse.Namespace):
    if arguments.scan_all:
        if arguments.scan_custom:
            raise ContradictingArguments(["-sA", "-sC"])
        return [s_name.value for s_name in ScannerNames]
    elif arguments.scan_custom:
        return arguments.scan_custom
    raise MissingArguments(["-sA", "-sC"])


def parse_wordlist_list(arguments: argparse.Namespace):
    return {s_name.value: getattr(arguments, f"wl_{s_name.value}", None) for s_name in ScannerNames}
