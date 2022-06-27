# SCA Reports
This script is meant to take the configurations from the yaml file and generate a report of failed checks for the selected SCA policies for the active agents at the moment of the execution of the script.
If you need to have this report only in the standard output, you need to execute a dry-run of the script (it will not generate a Service Now ticket). Otherwise it will generate one ticket per agent.

## Usage
```
usage: sca-reports.py [-h] -c CONFIG_FILE [-d] [--debug]

options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Path to the yaml config file
  -d, --dry-run         Only print the failed checks, don't create ticket
  --debug               Enable debug mode logging.
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
snow:
  url: "https://<snow_ip>/api/now/table/incident"
  username: "snow_user"
  password: "snow_pass"
  payload:
    caller_id: 
    u_contact: 
    u_type_level_1: 
    u_type_level_2: 
    u_type_level_3: 
    u_impacted_customers: 
    priority: 
    assignment_group: 
    short_description: 
    description: 
```