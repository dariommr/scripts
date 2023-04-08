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

## Script usage
This scripts makes use of a configuration file and parameters to execute the orders correctly.
You can find here, the script and a sample configuration file.
```shell
# python3 wazuh2sql.py -h
usage: wazuh2sql.py [-h] -c CONFIG_FILE -v VIS -t TABLE -d DAYS [--debug]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Path to the yaml config file
  -v VIS, --vis VIS     Visualization ID
  -t TABLE, --table TABLE
                        SQL Table to store the extracted data
  -d DAYS, --days DAYS  Number of days to query for
  --debug               Enable debug mode logging.
```

### Example
In this example, we will take the visualization with the ID: `a7874860-1e3e-11ed-a227-5d94cf79ab73` and we will insert its data into the table `flooding_alerts` in the DB configured in the `wazuh2sql_conf.yaml` file.
```shell
python3 wazuh2sql.py -c wazuh2sql_conf.yaml  -v "a7874860-1e3e-11ed-a227-5d94cf79ab73" -t flooding_alerts -d 30
```