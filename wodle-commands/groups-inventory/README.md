## Groups Inventory tool: groups-inventory.py
This script that takes the information about inventory from the Wazuh Manager’s databases through API calls and it inserts the information as alerts into Wazuh (and then Elasticsearch).
It must run locally on the Wazuh Manager and you can execute it manually or automatically with a wodle command.
```
<wodle name="command">
  <tag>groups-inventory</tag>
  <disabled>no</disabled>
  <command>/path/to/script/groups-inventory.py --group linux winsrv winwks --endpoint packages os</command>
  <interval>24h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
Remember to give execution permissions to the script: `chmod +x groups-inventory.py`

You need to pass two arguments to the script, `group` and `endpoint`. They can have one or more values:
```
# ./groups-inventory.py -h
usage: groups-inventory.py [-h] [--group GROUP [GROUP ...]] [--endpoint ENDPOINT [ENDPOINT ...]]

Get inventory information from agents and inject it in Wazuh as an alert.

optional arguments:
  -h, --help            show this help message and exit
  --group GROUP [GROUP ...]
                        Group name to query, use ALL for all the groups
  --endpoint ENDPOINT [ENDPOINT ...]
                        Specific syscollector endpoint to query. Use ALL for all the endpoints
```

You need to define the credentials file on `/var/ossec/etc/gi-pass.conf` that contains this:
```
{
  "username": "wazuh",
  "password": "wazuh"
}
```

**Examples:**
1. Getting Packages and OS information from groups linux, winsrv and winwks.
```
./groups-inventory.py --group linux winsrv winwks --endpoint packages os
```
2. Getting all the inventory information from all the groups:
```
./groups-inventory.py --group ALL --endpoint ALL
```
Note: This script does not compare if changes were made on the inventory, it will bring all the inventory information requested, all the times it is executed. This means that it will duplicate data in the Elasticsearch, that’s why it is recommended to not run it frequently. Weekly it would be a good choice, but you can run it also daily.

Once it runs, it inserts the data directly to the Wazuh Manager through a linux socket, and you should start seeing the information on your Kibana server UI:
![image](https://user-images.githubusercontent.com/37050249/147351670-61e7096c-0741-407d-a845-0d5806718e5f.png)
As you can see, you can get all the inventory information and filter it with groups.