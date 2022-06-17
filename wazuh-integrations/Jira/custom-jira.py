#!/usr/bin/env python
import os
import sys
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

################################################## USER PARAMETERS ###################################################

project_key = 'MKYIT'     # You can get this from the beggining of an issue key. For example, WS for issue key WS-5018
issuetype_name = 'Task'  # Check https://confluence.atlassian.com/jirakb/finding-the-id-for-issue-types-646186508.html. There's also an API endpoint to get it.
logfile = "integrations.log" #/var/ossec/logs/

################################################## Global variables ##################################################

alert_file = open(sys.argv[1])
user = sys.argv[2].split(':')[0]
api_key = sys.argv[2].split(':')[1]
hook_url = sys.argv[3]
debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == '--debug')

###################################################### Functions ######################################################

# Configuring logger
def set_logger(name, level, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)

    # Start logging config
    if level == "debug":
        logging.basicConfig(level=logging.DEBUG, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)
    else:
        logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

def send_jira(url, usr, pss, msg):
    headers = {'content-type': 'application/json'}
    data = json.dumps(msg)
    try:
        result = requests.post(url, data=data, headers=headers, auth=(usr, pss))
        logging.debug("Sending alert {}.".format(data))
    except Exception as e:
        logging.error("Error while contacting Jira: {}.".format(e))
        sys.exit(1)
    
    return result.status_code, result.text

################################################## Main workflow ##################################################

if __name__ == '__main__':
    if debug_enabled:
        set_logger("custom-jira", "debug", logfile)
    else:
        set_logger("custom-jira", "info", logfile)

    try:
        # Read the alert file
        alert_json = json.loads(alert_file.read())
        alert_file.close()
        # Extract issue fields
        alert_level = alert_json['rule']['level']
        ruleid = alert_json['rule']['id']
        description = alert_json['rule']['description']
        agentid = alert_json['agent']['id']
        agentname = alert_json['agent']['name']
        logging.info("Parameters loaded successfully")
    except Exception as e:
        logging.error("Error while loading parameters: {}.".format(e))
        sys.exit(1)

    # Generate the body
    try:
        issue_data = { "update": {}, "fields": {} }
        issue_data["fields"]["summary"] = 'Wazuh Alert: ' + description
        issue_data["fields"]["issuetype"] = { "name": issuetype_name }
        issue_data["fields"]["project"] = { "key": project_key }
        issue_data["fields"]["description"] = { "version": 1, "type": "doc", "content": [] }
        issue_data["fields"]["description"]["content"] = [{ "type": "paragraph", "content": [] }]
        issue_data["fields"]["description"] = '- Rule ID: ' + str(ruleid) + '\n- Alert level: ' + str(alert_level) + '\n- Agent: ' + str(agentid) + ' ' + agentname
        """
        issue_data["fields"]["description"]["content"][0]["content"] = [{ 
            "type": "text", 
            "text": '- Rule ID: ' + str(ruleid) + '\n- Alert level: ' + str(alert_level) + '\n- Agent: ' + str(agentid) + ' ' + agentname
        }]
        """
        logging.info("Body message created")
    except Exception as e:
        logging.error("Error while building the body: {}.".format(e))
        sys.exit(1)
    
    # Create the ticket
    code, response = send_jira(hook_url, user, api_key, issue_data)
    if code == 201:
        logging.info("Request sent successfully")
    else:
        logging.error("Request can not be processed, Error code {}. Activate debug to get more information".format(code))
    logging.debug("Request result: {} {}".format(code, response))
    sys.exit(0)
