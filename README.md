A pentest tool for websites, that performs several vulnerability scans.

# Types of Scans
in order to scan for all.. </br>
nickname of scan in parenthesis... </br>
results are saved... </br>
cache... </br>
requirements...  including OS...</br>

### Subdomain Scan (`dns`)

Iterates over a wordlist and probes the target host with each word set as the subdomain.</br>
The results are then contained inside a queue object and used for further scans.

* A host name can be passed with or without a subdomain. This scan performs probes on the target hostname, by replacing the passed subdomain with words from the wordlist
* In order to use a custom wordlist, `"--set-dnsscan-wl"` argument should be passed, followed by the path


### Content Scan (`content`)

Iterates over a wordlist and probes (in a brute manner) different endpoints by appending the words to the target hostname. </br>
A result is considered successful if the request status code is one of the following: `200`, `301`, `302`. If a forbidden status code is returned (`403`) and `403bypass` scan is enabled, further probing takes place where different kind of methods are attempted in order to bypass the forbidden status. Those attempts are also considered as success only if they manage to retrieve one of the aformentioned successful status code. <br>

* In order to use a custom wordlist, "--set-contentscan-wl" argument should be passed, followed by the path

### Bypass403 (`403bypass`)

Probes a url using different methods in order to bypass a `403` forbidden status code. </br> This scan is a subscan and shoudl only be invoked by  `Content Scan`.

* If listing a custom scan list rather than using the `-sA` option, this scan should be listed as well, otherwise it would be disabled

### NMAP Scan (`nmap`)

Performs a simple NMAP scan on the host target.

* Custom ports should be passed using the `--set-nmapscan-ports` argument, in the same format they are passed in NMAP,</br> i.e: `"21-25,80,139"`
* Custom commandline arguments for the scan should be passed using the `--set-nmapscan-cmdline_args` argument,</br> i.e: `"-sV -sU -sS"`

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and are not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
