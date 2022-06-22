#!/var/ossec/framework/python/bin/python3

import datetime
import json
import os
import sys
import time
import logging
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

################################################## Global variables ##################################################

alert_file = open(sys.argv[1])
hec_token = sys.argv[2]
hook_url = sys.argv[3]
alert_json = json.loads(alert_file.read())
alert_file.close()
debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')

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

def send_splunk(url, token, msg):
    token = sys.argv[2].split(":")
    str_token = token[0]+" "+token[1]
    headers = {
        'Content-Type': 'application/json',
        'Authorization': str_token,
        'Accept-Charset': 'UTF-8'
    }
    try:
        result = requests.post(url, data=json.dumps(msg), headers=headers)
        logging.debug("Sending alert {}.".format(msg))
    except Exception as e:
        logging.error("Error while contacting Splunk: {}.".format(e))
        sys.exit(1)
    
    return result.text
    
################################################## Main workflow ##################################################

if __name__ == '__main__':
    if debug_enabled:
        set_logger("custom-splunk", "debug", "/var/ossec/logs/integrations.log")
    else:
        set_logger("custom-splunk", "info", "/var/ossec/logs/integrations.log")

    try:
        logging.info("Reading the alert")
        splunk = {}
        splunk['event'] = alert_json
        splunk['sourcetype'] = '_json'

        splunk['source'] = 'wazuh-manager'
        if 'manager' in splunk['event']:
            if 'name' in splunk['event']['manager']:
                splunk['source'] = splunk['event']['manager']['name']

        splunk['time'] = int(time.time())
        if 'timestamp' in splunk['event']:
            dt = datetime.datetime.strptime(
                splunk['event']['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
            splunk['time'] = int((dt - datetime.datetime(
                1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds())

        if 'agent' in splunk['event']:
            if 'name' in splunk['event']['agent']:
                splunk['host'] = splunk['event']['agent']['name']

        res = send_splunk(hook_url, hec_token, splunk)
        logging.info("Alert send result: {}".format(res))
    except Exception as e:
        logging.error("Error on the integration process: {}.".format(e))