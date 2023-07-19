## Introduction
This is script is intended to be used as a tool to extract security events from Microsoft Defender administration through its API.

## Prerequisites
Copy the script to the Wazuh Manager and place it in the wodles folder (`/var/ossec/wodles/`) and then change its permissions:
```
chmod ug+x /var/ossec/wodles/win-defender-api.py
chown root:ossec /var/ossec/wodles/win-defender-api.py
```
## How to use it
You can use the integration script manually by running it as a command, or automatically through the Wazuh Manager as a wodle command.
```
# /var/ossec/wodles/win-defender-api.py -h
usage: win-defender-api.py [-h] --days days --tenantId tenantId --clientId clientId --clientSecret clientSecret [--debug]

Wazuh - Microsoft Defender Security information.

optional arguments:
  -h, --help            show this help message and exit
  --days days           How many days to fetch activity logs.
  --tenantId tenantId   Application tenant ID.
  --clientId clientId   Application client ID.
  --clientSecret clientSecret
                        Client secret.
  --debug               Enable debug mode logging.
```
Be aware that the `--debug` option will output to the log all the events fetched with the API.

### Manually
You can run it manually using the parameters listed above. For instance:
```
/var/ossec/wodles/win-defender-api.py --days 100 --tenantId ZZZZZZZZZ --clientId XXXXXXXXX --clientSecret YYYYYYYYY
```
### Automatically
It can be run through Wazuh Manager automatically with a wodle command. For this, you have to add the configuration in the `/var/ossec/etc/ossec.conf` file:
```
  <wodle name="command">
    <disabled>no</disabled>
    <tag>win_defender_api</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/win-defender-api.py --days 100 --tenantId ZZZZZZZZZ --clientId XXXXXXXXX --clientSecret YYYYYYYYY</command>
    <interval>1d</interval>
    <ignore_output>yes</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>300</timeout>
  </wodle>
```
This will ingest all the events (in `JSON` format) to the Wazuh Manager, you just need to adjust your ruleset to convert them into Wazuh Alerts.

## Writing the rule
This rule will catch all the logs from the script and convert them into alerts:
```
<group name="win-defender,">
  <rule id="293400" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration">microsoft-defender</field>
    <description>Microsoft Defender Rules</description>
  </rule>
</group>
```
Other Configurations: You can change some configurations inside the script to adjust it to your environment, such as logs location and Proxy.
