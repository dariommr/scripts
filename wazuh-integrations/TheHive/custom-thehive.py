#!/usr/bin/env python
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# Read configuration parameters
alert_file = open(sys.argv[1])
api_key = sys.argv[2]
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extracting some information from the alert
alert_id = alert_json['id']
rule_id = alert_json['rule']['id']
rule_level = alert_json['rule']['level']
rule_desc = alert_json['rule']['description']
rule_groups = alert_json['rule']['groups']
agent_name = alert_json['agent']['name']
manager_name = alert_json['manager']['name']
location = alert_json['location']

# Building the request.
body = {}
body['title'] = rule_desc
body['description'] = "An alert with rule id "+str(rule_id)+" and level "+str(rule_level)+" has been triggered"
body['type'] = "external"
body['source'] = manager_name
body['sourceRef'] = "id: "+alert_id
body['tags'] = rule_groups
body['severity'] = 3
body['tlp'] = 3
headers = {'content-type': 'application/json', 'Authorization': 'Bearer '+api_key }

# Executing the request
response = requests.post(hook_url, data=json.dumps(body), headers=headers)
print(response.text)

sys.exit(0)