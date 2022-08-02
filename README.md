A pentest tool for websites, that performs several vulnerability scans.

# Types of Scans
in order to scan for all.. </br>
nickname of scan in parenthesis... </br>
results are saved... </br>
cache... </br>

### Subdomain Scan (`dns`)

Iterates over a wordlist and probes the target host with each word set as the subdomain.</br>
The results are then contained inside a queue object and used for further scans.

* A host name can be passed with or without a subdomain. This scan performs probes on the target hostname, by replacing the passed subdomain with words from the wordlist
* In order to use a custom wordlist, `"--set-dnsscan-wl"` argument should be passed, followed by the path


### Content Scan (`content`)

Iterates over a wordlist and probes (in a brute manner) different endpoints by appending the words to the target hostname. </br>
A result is considered successful if the request status code returns one of the following: `[200, 301, 302]`


### Bypass403 (`403bypass`)

### NMAP Scan (`nmap`)

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and are not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
