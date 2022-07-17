import os
import argparse

from .default_values import WordlistDefaultPath, ScannerNames


def get_argument_parser() -> argparse.ArgumentParser:
    # Create the parser and add arguments
    left_pad = 2 * " "
    ljust_width = 22
    default_results_path = os.path.join(os.getcwd(), "results")
    default_contentscan_wlpath = os.path.join(os.getcwd(), WordlistDefaultPath.ContentScanner)
    default_dnsscan_wlpath = os.path.join(os.getcwd(), WordlistDefaultPath.DNSScanner)
    parser = argparse.ArgumentParser(description=f'description:\n{left_pad}'
                                                 f'a variety of pentest tools for scanning vulnerabilities'
                                                 f' on a given host',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     usage=f""
                                           f"\n{left_pad}"
                                           f"{'WebRecon -sA'.ljust(ljust_width)}run all scans (default)"
                                           f"\n{left_pad}"
                                           f"{'WebRecon -sC *scans'.ljust(ljust_width)}"
                                           f"run custom scans (i.e: `WebRecon -sC dns content`)",
                                     epilog="Types of scans:\n"
                                            f"{left_pad}"
                                            f"* {ScannerNames.DnsScan} -> a recursive multi-threaded scan for subdomains\n"
                                            f"{left_pad}"
                                            f"* {ScannerNames.ContentScan} -> a multi-threaded content scan for vulnerable pages\n"
                                            f"{left_pad}"
                                            f"* {ScannerNames.BypassScan} -> perform attempts to bypass a 403 page "
                                            f"(requires scan: {ScannerNames.ContentScan})\n"
                                            f"{left_pad}"
                                            f"* {ScannerNames.NmapScan} -> an nmap port scan")
    parser.add_argument(dest='target_url', type=str, help="The target host url")

    parser.add_argument("-sA", "--scan-all", dest='scan_all', action='store_true',
                        help="perform all scans")
    parser.add_argument("-sC", "--scan-custom", dest='scan_custom', action="store", nargs="+", metavar=("", "s1, s2"),
                        type=str, help="custom scans (case-sensitive)")
    # TODO if -A, ignore the rest above
    # TODO colors

    parser.add_argument(f"--set-{ScannerNames.DnsScan}scan-wl", action='store', dest=f'wl_{ScannerNames.DnsScan}',
                        metavar="PATH_TO_WORDLIST",
                        type=str, default=default_dnsscan_wlpath,
                        help=f"path to the dns scan wordlist"
                             f" (default: {default_dnsscan_wlpath})")

    parser.add_argument(f"--set-{ScannerNames.ContentScan}scan-wl", action='store',
                        dest=f'wl_{ScannerNames.ContentScan}', metavar="PATH_TO_WORDLIST",
                        type=str, default=default_contentscan_wlpath,
                        help=f"path to the content scan wordlist"
                             f" (default: {default_contentscan_wlpath})")

    parser.add_argument("--set-results-directory", dest='results_path', metavar="PATH_TO_DIRECTORY",
                        type=str, default=default_results_path,
                        help=f"path to the main results directory"
                             f" (default: {default_results_path})")  # TODO make sure default is PWD

    return parser


def parse_scan_list(arguments: argparse.Namespace):
    if arguments.scan_all:
        if arguments.scan_custom:
            raise Exception("Custom scan list cannot be set with -sA")
        return [s_name.value for s_name in ScannerNames]
    elif arguments.scan_custom:
        return arguments.scan_custom
    raise Exception("Please choose scans to run (-sA to perform all scans)")


def parse_wordlist_list(arguments: argparse.Namespace):
    return {s_name.value: getattr(arguments, f"wl_{s_name.value}", None) for s_name in ScannerNames}
