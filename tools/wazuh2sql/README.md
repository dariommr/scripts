# Wazuh Dashboard visualizations to SQL converter Tool
This is a Python script intended to be user to extract visualizations (Tables) from a Wazuh Dashboard and inject them into SQL Databases.

## Pre-requisites
### Install Python Modules
Install the PyODBC module:
```shell
# Using the python interpreter present on the system
pip install pyodbc

# Using the Wazuh framework (If the script will run in a wodle command)
/var/ossec/framework/python/bin/pip3 install pyodbc
```

Install the YAML module:
```shell
# Using the python interpreter present on the system
pip install pyyaml

# Using the Wazuh framework (If the script will run in a wodle command)
/var/ossec/framework/python/bin/pip3 install pyyaml
```

### Configure the ODBC to connect to the SQL Server
1. Install the ODBC module unixodbc for Linux, and the MSSQL ODBC Driver FreeTDS
```shell
# In Debian
sudo apt-get install tdsodbc unixodbc

# In CentOS
sudo yum install unixODBC
sudo yum install freetds
```

2. Modify the configuration files
```ini
# vi /etc/odbc.ini
[WAZUHTEST]
Driver      = FreeTDS
Servername  = WAZUHTEST
Database    = indexer-data

# vi /etc/odbcinst.ini
# In Debian
[FreeTDS]
Driver          = /usr/lib/x86_64-linux-gnu/odbc/libtdsodbc.so
Setup           = /usr/lib/x86_64-linux-gnu/odbc/libtdsS.so
UsageCount      = 1
# In CentOS
[FreeTDS]
Driver          = /usr/lib64/libtdsodbc.so
Setup           = /usr/lib64/libtdsS.so
UsageCount      = 1

# vi /etc/freetds/freetds.conf
[WAZUHTEST]
        host = <SQL_SERVER_IP_ADDRESS>
        port = <SQL_SERVER_PORT>
        tds version = 7.3
```
To select the correct `tds version` please refer to this [section](https://github.com/dariommr/scripts/tree/master/tools/wazuh2sql#choosing-the-tds-version).

### Table columns requisites
The table should have one fixed column named `timestamp`, and one column for each metric, if you are using the metric type *count*, you should have a column named `count`. If you have more metrics in your visualization, you should have more columns with the name of the metric type.
For instance, in our example we have:

| rule_id | rule_description                                      | agent_name | count | timestamp                  |
| ------- | ----------------------------------------------------- | ---------- | ----- | -------------------------- |
| 773001  | The service apparmor.service is in exited status      |  wzh-man01 | 233   | 2023-06-07 11:53:17.198554 |
| 773001  | The service console-setup.service is in exited status |  wzh-man01 | 233   | 2023-06-07 11:53:17.198554 |

Where `rule_id`, `rule_description` y `agent_name` are the columns defined in the configuration file, while the column `count` is present because the metric used in the visualization. The `timestamp` column is needed to know the time when the data was added to the database, therefore needs to be set up in the destination table also.

## Script usage
This scripts makes use of a configuration file and parameters to execute the orders correctly.
You can find here, the script and a sample configuration file.
### Scripts:
- https://github.com/dariommr/scripts/blob/master/tools/wazuh2sql/wazuh2sql.py
- https://github.com/dariommr/scripts/blob/master/tools/wazuh2sql/wazuh2sql_conf.yaml
### Usage:
```shell
# python3 wazuh2sql.py -h
usage: wazuh2sql.py [-h] -c CONFIG_FILE -v VIS -t TABLE -d DAYS [--debug] [--dry-run]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Path to the yaml config file
  -v VIS, --vis VIS     Visualization ID
  -t TABLE, --table TABLE
                        SQL Table to store the extracted data
  -d DAYS, --days DAYS  Number of days to query for
  --debug               Enable debug mode logging.
  --dry-run             Show results to screen. Do not store on SQL.
```

### Example:
In this example, we will take the visualization with the ID: `a7874860-1e3e-11ed-a227-5d94cf79ab73` and we will insert its data into the table `flooding_alerts` in the DB configured in the `wazuh2sql_conf.yaml` file.
```shell
python3 wazuh2sql.py -c wazuh2sql_conf.yaml  -v "a7874860-1e3e-11ed-a227-5d94cf79ab73" -t flooding_alerts -d 30
```

## Apendix
### Getting the Visualization ID:
You can obtain the ID, you need to navigate to *Menu > Visualize* and select the visualization you need (Table only), then you need to extract the ID from here:
![image](https://user-images.githubusercontent.com/37050249/230723543-069c2034-dbc6-45d1-85a3-2c2ea52c5eec.png)

### Choosing the TDS version
In the `freetds.conf` file you need to specify the `tds version` setting in order to connect correctly to the SQL Server you need to, for this, please take a look at this document: https://www.freetds.org/userguide/ChoosingTdsProtocol.html
