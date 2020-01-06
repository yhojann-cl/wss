# WSS v2.5.3-beta

[![Chilean](https://img.shields.io/badge/From-Chile-blue.svg)](https://es.wikipedia.org/wiki/Chile)
[![License](https://img.shields.io/badge/license-GPL%20(%3E%3D%202)-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Contributions](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/WHK102/wss/issues)
[![Donations](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/whk102)

WSS (WHK Subdomains Scanner) is a tool for **pentesters**, which performs the
search of subdomains and performs actions on each host name found.

The application works with two groups of modules:

- Subdomain search methods.
- Filters.

The **filters** are modules that process the results to add more information
such as the basic scan of ports and the search for services *http*.


## Requirements

- Python 3.
- Google API-Key in `modules/subdomains/google.py` (optional, by default comes a
  gift).
- Installation of the modules declared in `requirements.txt` using pip3.

Note: Character coding problems have been reported using Microsoft Windows, so
it is recommended for the moment that we are looking for a solution, using some
GNU / Linux distribution since the encoding of the files is better respected.


## Installation

It is not necessary an installation in the Operating System, it is enough with
the installation of the required modules in `requirements.txt` to work.

The requirements can be installed as follows:

    pip3 install --user -r requirements.txt


## Use

Let's cut to the chase:

    $ python3 wss.py
    WSS (WHK Subdomains Scanner)
    Version : v2.5.2-beta
    Contact : whk@elhacker.net
    -----------------------------------------
       
    Usage: wss.py [options]
       
    Result: A tree of host names (subdomains) found grouped by IP address.
       
    Options:
      -h, --help     Show the help message.
          --host     The host name to search.
      -a, --api      WSS API REST
                      Parameters:
                       <host>:<port>:<debug>
                      Examples:  
                       -a :3000:off
                       -a 3000
                       -a 127.0.0.1:3000
      -m, --methods  List of methods.
                     Available methods:
                       0: DNS/AXFR query.
                       1: DNS queries to common records (TXT, MX, SPF, etc).
                       2: Search on virustotal.com.
                       3: Search on robtex.com.
                       4: Search on crt.sh.
                       5: Search on certificatedetails.com.
                       6: Search on google.com (if have the api-key).
                       7: Search on bing.com.
                       8: Search on dnsdumpster.com.
                       9: Brute force of 4 characters.
                       a: Use a dictionary of known subdomains.
                     Examples:
                       -m 01
                       -m 49a
                       -m 0123456789a
                     By default all available methods are used.
      -f, --filters  List of filters.
                     Available filters:
                       0: Search open ports for each IP address using low level",
                          sockets (SYN-ACK), very fast but need privileges, only
                          requires 3 threads.
                       1: Search open ports for each IP address. The search is",
                          basic, it does not replace conventional software such",
                          as nmap. Use by default 500 threads.",
                       2: Search HTTP services in the ports found by filter 0,",
                          otherwise it will use a list of known http ports. Use",
                          by default 20 threads. It does not need privileges but",
                          it is a very slow method.",
                     Examples:
                       -f 0
                       -f 02
                     By default, no filter is used.
       
    Examples:
      wss.py --host starbucks.com -f 2
      sudo wss.py --host starbucks.com -f 02
      sudo wss.py --host dev.starbucks.com -f 02

You can try a quick test:

    sudo python3 wss.py --host elhacker.net -m 4 -f 02

An example of the final result of a search:

    4 subdomains were found
        ├── x.x.x.x
        │   ├── Hostnames
        │   │   ├── ssh.example.com
        │   │   └── www.example.com
        │   │       └── HTTP services
        │   │           └── http://www.example.com/ (HTTP-200: Example Website)
        │   └── Ports
        │       ├── 22
        │       └── 80
        └── Unknown IP address
            └── Hostnames
                ├── foo.example.com
                └── bar.example.com
    

## Lenguaje

The translations and texts files are in the directory
`resources/strings/*.json` where each file name is equal to the iso code of
language.

The application will detect the language used by default in the System Operative
and will search the corresponding translation file, if it does not exist will
use the default language `en.json`.


## Advantage

In addition to search in public services already known, you can use brute force
by obtaining new subdomains without using databases. It also provides a tree of
associated IP addresses to know redundant subdomains, which saves time in
reviewing the services.

The application has a modular separation of the methods and filters,
facilitating the creation of new customized modules.


## Tested in

- Ubuntu 18.04.2 LTS
- CentOS 7
- Debian 9
- Kali 2019.2
