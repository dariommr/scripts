# Scripts

## Elasticsearch Indices Reindex Tool: reindex.sh
**USAGE:** `reindex.sh (-a|--all yes | -f|--file /path/file) -s|--server https://elastic_address:port -u|--user user -p|--pass password`
**Note:** The script is not yet complete, I have to develop the `ALL` feature

## Archived Logs Removal Tool: alrt.py

## Wazuh Cluster Monitoring Tool: monitor-cluster.py
This tool can run in automatic or manual mode, in automatic mode, there is no need to pass arguments to it. In manual mode you need to specify only one argument.
Tool parameters:
```
# Usage:
#       monitor-cluster.py update|status
# Parameters:
#       update     Use this to create, or update the baseline file
#       status     Gets the current status of the cluster
# No parameters: The tool runs in automatic mode, if the baseline file is not crated
#                it creates it, if not it runs the status check.
```

## Tool to dump all Wazuh Indices in Elasticsearch to JSON: elastic-dump.sh
