**READ THE DISCLAIMER** </br>
</br> A pentesting tool for target websites, that performs several vulnerability scans. 

![image](https://user-images.githubusercontent.com/59119926/183238692-d01a8f69-20cf-4b7f-8954-b7a7c119c9bf.png)



# Requirements
Make sure to set the right file permissions: `chmod u+x WebRecon.py`

### Dependencies
Python library dependencies are listed inside `requirements.txt`, and should be installed using `pip3` command. </br>
NMAP should be installed as well.

### OS

Currently only Kali LINUX OS is supported.

# Types of Scans
By default `-sA` (scanAll) argument is true, which means all scanners would run. </br> It is possible to pass a custom list of scans by using the argument `-sC` (scanCustom) followed by a list of scans. The nicknames of the scans are listed in the parenthesis next to each scanner header name below. </br>

An example of a command that would start all scans, without cache, using custom wordlists on target `www.____.com`:

```
./WebRecon.py https://www.___.com -sA --set-contentscan-wl /root/PycharmProjects/content_wl.txt2 --set-dnsscan-wl /root/PycharmProjects/dns_wl.txt2 --disable-cache
```

* The default wordlists are basic. You can pass custom ones using cmdline arguments
* A good source for wordlists: https://github.com/danielmiessler/SecLists

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
* Most of the methods in this scanner were converted from another known GitHub repo, credit goes to https://github.com/offsecdawn/403bypass

### NMAP Scan (`nmap`)

Performs a simple NMAP scan on the host target.

* Custom ports should be passed using the `--set-nmapscan-ports` argument, in the same format they are passed in NMAP,</br> i.e: `"21-25,80,139"`
* Custom commandline arguments for the scan should be passed using the `--set-nmapscan-cmdline_args` argument,</br> i.e: `"-sV -sU -sS"`

# Output
### Results
For each hostname, a directory is created with the hostname as its name. Inside the directory, subdirectories are created with the full name of the subdomain and hostname. (each subdomain has its own subdirectory). </br>
Total results and subdomain scan results are saved in a `.txt` file inside the main hostname directory. <br>
Example of the total results output text file:
![image](https://user-images.githubusercontent.com/59119926/183238731-79eb3f9b-0934-4b30-bf43-1446070c81a4.png)



Other scans save results inside the subdirectory named by the full hostname + subdomain. </br>
Example: `results/hostname_com/www_hostname_com/results...txt`

* The default path for results is the current working directory. It can be changed by passing the path following the argument: `--set-results-directory`

### Cache
By default, cache is enabled. Cache files that are older than 30 minutes would be disregarded.

* It is possible to disable cache by passing the following argument: `--disable-cache`

### Exceptions
No exceptions (other than the ones handled inside the code) are allowed. Any other exception would be logged under `error log` and abort the scan. </br>


# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and are not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
