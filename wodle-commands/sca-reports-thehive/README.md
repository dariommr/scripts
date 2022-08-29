# SCA Reports
This script is meant to take the configurations from the yaml file and generate a report of failed checks for the selected SCA policies for the active agents at the moment of the execution of the script.
If you need to have this report only in the standard output, you need to execute a dry-run of the script (it will not generate a Service Now ticket). Otherwise it will generate one ticket per agent.

## Usage
```
usage: sca-reports-thehive.py [-h] -c CONFIG_FILE [-k CHECKS [CHECKS ...]] [-d] [-l CDBLIST] [--debug]

options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Path to the yaml config file
  -k CHECKS [CHECKS ...], --checks CHECKS [CHECKS ...]
                        `failed` or `not-applicable` are allowed
  -d, --dry-run         Only print the failed checks, don't create ticket
  -l CDBLIST, --cdblist CDBLIST
                        Name of the cdb list containing the excluded hostnames
  --debug               Enable debug mode logging.             Enable debug mode logging.
```

## Configuration file:
```
---
wazuh:
  url: "https://localhost:55000"
  username: "wazuh"
  password: "wazuh"
  policy_id: 
  - "sca_win_audit"
  - "cis_win2016"
  - "cis_debian10"
thehive:
  url: "http://<THEHIVE_IP>:9000/api/v1/case"
  api_key: "<API_KEY>"
```