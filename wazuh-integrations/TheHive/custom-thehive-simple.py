#!/bin/python3

import os
import json
import sys
import logging
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

################################################## Global variables ##################################################

alert_file = open(sys.argv[1])
api_key = sys.argv[2]
hook_url = sys.argv[3]
alert_json = json.loads(alert_file.read())
alert_file.close()

log_file = "/var/ossec/logs/integrations.log"
DEBUG = False

################################################## Common functions ##################################################

# Enables logging and configure it
def set_logger(name, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)
    formatter = logging.Formatter(format)
    if DEBUG:
        logging.getLogger('').setLevel(logging.DEBUG)
    else:
        logging.getLogger('').setLevel(logging.INFO)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    logging.getLogger('').addHandler(streamHandler)
    
    if logfile:
        fileHandler = logging.FileHandler(logfile)
        fileHandler.setFormatter(formatter)
        logging.getLogger('').addHandler(fileHandler)

# Write the body of the TheHive Alert
def build_alert(wazuh_alert):
    try:
        description = "An alert with rule id "+str(wazuh_alert['rule']['id'])+" and level "+str(wazuh_alert['rule']['level'])+" has been triggered"
        severity = wazuh_alert['rule']['level'] // 4
        if severity < 1:
            severity = 1
        alert = {   "title": wazuh_alert['rule']['description'],
                    "description": description,
                    "type": "external",
                    "source": wazuh_alert['manager']['name'],
                    "sourceRef": "id: {}".format(wazuh_alert['id']),
                    "tags": wazuh_alert['rule']['groups'],
                    "severity": severity,
                    "tlp": severity - 1}
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while writing the alert: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    return alert

def send_thehive(url, api, msg):
    headers = {     "content-type": "application/json", 
                    "Authorization": "Bearer {}".format(api) }
    data = json.dumps(msg)
    try:
        logging.debug("Sending alert {}.".format(data))
        result = requests.post(url, data=data, headers=headers)
        if result.status_code != 201:
            raise Exception("Code {} - {}".format(result.status_code, result.text))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while contacting TheHive: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    return result.text

################################################## Main Workflow ##################################################
if __name__ == "__main__":
    set_logger("thehive-integration", log_file)
    
    logging.debug("Starting TheHive Integration")
    body = build_alert(alert_json)
    logging.debug("Alert building process completed successfully: {}".format(body))
    response = send_thehive(hook_url, api_key, body)
    resp_dict = json.loads(response)
    logging.info("Alert sent to TheHive server. Response ID: {}".format(resp_dict["id"]))