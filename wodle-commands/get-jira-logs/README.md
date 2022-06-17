# Get Jira logs from API service

## Rationale
This script connects to the Jira API service to extract logs and inject them to the Wazuh Socket.

## Usage
```
usage: get-jira-logs.py [-h] --hours days --email email --token token [--force] [--debug]

Wazuh - Jira Logs Integration Script.

optional arguments:
  -h, --help     show this help message and exit
  --hours days   How many hours to fetch activity logs.
  --email email  The Jira email ID.
  --token token  Jira user token.
  --force        It will force sending all logs collected. It can cause duplicated alerts
  --debug        Enable debug mode logging.
```

### Example
```
/var/ossec/wodles/get-jira-logs.py --hours 2 --email email@company.com --token aaabbbcccdddeeefff --force
```
