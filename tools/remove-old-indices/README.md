## Tool for removing old indices from Wazuh Indexer/OpenSearch/Elasticsearch.
```shell
# ./remove_old_indices.py -h
usage: remove_old_indices.py [-h] -c CONFIG_FILE -d DAYS [--debug] [--dry-run]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Path to the yaml config file
  -d DAYS, --days DAYS  Number of days to query for
  --debug               Enable debug mode logging.
  --dry-run             Show results to screen. Do not store on SQL.
```

**Example:**
```shell
./remove_old_indices.py -c remove_old_indices.yaml -d 365
2023-06-24 17:46:43,716 wzh-man01 remove-old-indices: [INFO] Obtaining all Indices
2023-06-24 17:46:43,768 wzh-man01 remove-old-indices: [INFO] Listing 428 indices
2023-06-24 17:46:44,609 wzh-man01 remove-old-indices: [INFO] 19 Indices deleted. 0 Couldn't be deleted
```