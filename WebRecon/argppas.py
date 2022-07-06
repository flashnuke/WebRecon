import argparse

# Create the parser and add arguments
parser = argparse.ArgumentParser(description='A variety of pentest tools for scanning vulnerabilities on websites',
                                 formatter_class=argparse.RawTextHelpFormatter,
                                 usage=f""
                                       f"\n\t{'WebRecon -sA'.ljust(25)}Run all scans (default)"
                                       f"\n\tWebRecon -sC scan[1], scan[2] ... scan[n]",
                                 epilog="Types of scans:\n"
                                        "\t* dns -> a recursive multi-threaded scan for subdomains\n"
                                        "\t* content -> a multi-threaded content scan for vulnerable pages\n"
                                        "\t* 403bypass -> perform attempts to bypass a 403 page (requires scan: content)\n"
                                        "\t* nmap -> an nmap port scan")
parser.add_argument(dest='target_host', type=str, help="The target host")

parser.add_argument("-sA", "--scan-all", dest='argument4', action='store_true',
                    help="Perform all scans")
parser.add_argument("-sC", "--scan-custom", dest='scans', action="store", nargs="+", metavar=("", "scan1, scan2"),
                    type=str, help="A custom list of scans to perform from the list at the bottom (case-sensitive)")
# TODO if -A, ignore the rest above
# TODO colors

parser.add_argument("--set-dnsscan-wl", action='store', dest='wl_dnsscan', metavar="PATH_TO_WORDLIST",
                    type=str, help="Path to the dns scan wordlist")

parser.add_argument("--set-contentscan-wl", action='store', dest='wl_contentscan', metavar="PATH_TO_WORDLIST",
                    type=str, help="Path to the content scan wordlist")

parser.add_argument("--set-results-directory", dest='wl_contentscan', metavar="PATH_TO_DIRECTORY",
                    type=str, default=".", help="Path to the main results directory")  # TODO make sure default is PWD


# Parse and print the results
args = parser.parse_args()
print(args.target_host)
