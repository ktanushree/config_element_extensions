# CloudGenix Config Element Extensions (Preview)
This utility is used to configure device level extension configurations. Using this script, the user can enable or disable applications such as SSH, ICMP or BGP for prefixes on a certain interface.

#### Synopsis
This enables policying of application traffic for configured prefixes to either allow or deny on the configured interface. The user can either configure a single extension configuration via the CLI or bulk configuration using a CSV file. 
The CSV file should contain the following headers:
site,element,interface,prefix,app,action


#### Requirements
* Active CloudGenix Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.2.1b1 - <https://github.com/CloudGenix/sdk-python>
* ProgressBar2

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `config_element_extensions.py`. 

### Examples of usage:
Configuration via CLI:
```
./config_element_extensions.py -SN Sitename -EN Elementname -IN Interfacename -IP 10.32.15.0/24 -AP SSH -AC ALLOW
```

Configuration via CSV:
```angular2
./config_element_extensions.py -f csvfilename.csv
```

Use the -H hours to specify the time delta in hours for the event query.

Help Text:
```angular2
Tanushrees-MacBook-Pro:config_element_extensions tanushreekamath$ ./config_element_extensions.py -h
usage: config_element_extensions.py [-h] [--controller CONTROLLER]
                                    [--email EMAIL] [--pass PASS]
                                    [--site SITE] [--element ELEMENT]
                                    [--interface INTERFACE]
                                    [--application APPLICATION]
                                    [--ipprefix IPPREFIX] [--action ACTION]
                                    [--filename FILENAME]

CloudGenix: Config SSH.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod:
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

SSH Config Specific information:
  IP prefix and interface information to enable SSH

  --site SITE, -SN SITE
                        Name of the Element
  --element ELEMENT, -EN ELEMENT
                        Name of the Element
  --interface INTERFACE, -IN INTERFACE
                        Interface where you want to enable SSH
  --application APPLICATION, -AP APPLICATION
                        Application you want to add controls to. Accepted
                        values: BGP, DHCP, PING, SNMP, SSH, TRACEROUTE,
                        SpokeHASync
  --ipprefix IPPREFIX, -IP IPPREFIX
                        IP Prefix
  --action ACTION, -AC ACTION
                        Action for config. Accepted values: allow or deny
  --filename FILENAME, -f FILENAME
                        CSV file containing configuration information. CSV
                        header should match:
                        site,element,interface,ipprefix,app,action

```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b2** | Minor bug fixes. |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>
 
