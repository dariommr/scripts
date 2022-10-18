# VD Reports
This script is meant to take the configurations from the yaml file and generate a report of vulnerabilities for the active agents at the moment of the execution of the script.
If you need to have this report only in the standard output, you need to execute a dry-run of the script (it will not generate a Service Now ticket). Otherwise it will generate one ticket per agent.

## Usage
```
usage: vd-report-thehive.py [-h] -c CONFIG_FILE [-g GROUPS [GROUPS ...] | -i IDS [IDS ...] | --all] [-d] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Path to the yaml config file
  -g GROUPS [GROUPS ...], --groups GROUPS [GROUPS ...]
                        Agent groups names separated by space
  -i IDS [IDS ...], --ids IDS [IDS ...]
                        IDs of the agents
  --all                 All the agents
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

thehive:
  url: "http://<THEHIVE_IP>:9000/api/v1/case"
  api_key: "<API_KEY>"
```

## Screenshots
![image](https://user-images.githubusercontent.com/37050249/196460401-98efcee3-a711-4288-9d4e-7d4b6a5980f1.png)
