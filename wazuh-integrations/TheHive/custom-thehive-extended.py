#!/var/ossec/framework/python/bin/python3

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
        description = "**An alert with rule id "+str(wazuh_alert['rule']['id'])+" and level "+str(wazuh_alert['rule']['level'])+" has been triggered**"
        description_added = False
        severity = wazuh_alert['rule']['level'] // 4
        if severity < 1:
            severity = 1
        # If the Wazuh Alert is triggered by a Windows Event
        if wazuh_alert["location"] == "EventChannel":
            system_data = "**System:**\r\n"
            for key in wazuh_alert["data"]["win"]["system"]:
                if key == "message":
                    system_data += "- {}:\r\n\r\n```\n{}\r\n```".format(key, wazuh_alert["data"]["win"]["system"][key]) +"\r\n"
                else:
                    system_data += "- {}: {}".format(key, wazuh_alert["data"]["win"]["system"][key]) +"\r\n"
            event_data = "**Event Data:**\r\n"
            for key in wazuh_alert["data"]["win"]["eventdata"]:
                event_data += "- {}: {}".format(key, wazuh_alert["data"]["win"]["eventdata"][key]) +"\r\n"
            description += "\r\n\r\n"+ system_data +"\n"+ event_data
            description_added = True
        # If the Wazuh Alert is triggered by a FIM event
        if wazuh_alert["location"] == "syscheck":
            syscheck_data = "**File Integrity Monitoring data:**\r\n"
            for key in wazuh_alert["syscheck"]:
                syscheck_data += "- {}: {}".format(key, wazuh_alert["syscheck"][key]) +"\r\n"
            description += "\r\n\r\n"+ syscheck_data
            description_added = True
        # If the Wazuh Alert is triggered by a VirusTotal Integration
        if wazuh_alert["location"] == "virustotal":
            virustotal_data = "**VirusTotal Integration data:**\r\n"
            for key in wazuh_alert["data"]["virustotal"]:
                if type(wazuh_alert["data"]["virustotal"][key]) is dict:
                    virustotal_data += "- {}:\r\n\r\n```\n{}\r\n\r\n```\r\n".format(key, json.dumps(wazuh_alert["data"]["virustotal"][key], indent=4, sort_keys=True))
                else:
                    virustotal_data += "- {}: {}".format(key, wazuh_alert["data"]["virustotal"][key]) +"\r\n"
            description += "\r\n\r\n"+ virustotal_data
            description_added = True
        # If the Wazuh Alert is triggered by a Vulnerability detector module
        if wazuh_alert["location"] == "vulnerability-detector":
            vd_data = "**Vulnerability Detector data:**\r\n"
            for key in wazuh_alert["data"]["vulnerability"]:
                if type(wazuh_alert["data"]["vulnerability"][key]) is dict:
                    vd_data += "- {}:\r\n\r\n```\n{}\r\n\r\n```\r\n".format(key, json.dumps(wazuh_alert["data"]["vulnerability"][key], indent=4, sort_keys=True))
                else:
                    vd_data += "- {}: {}".format(key, wazuh_alert["data"]["vulnerability"][key]) +"\r\n"
            # If you want to ignore Solved vulnerabilities, uncomment the following lines:
            #if wazuh_alert["data"]["vulnerability"]["status"] == "Solved":
            #    raise Exception("Vulnerability Solved, discarding alert")
            description += "\r\n\r\n"+ vd_data
            description_added = True
        # For all others type of events than the previous
        if not description_added:
            description += "\r\n```\n{}\r\n\r\n```".format(json.dumps(wazuh_alert["data"], indent=4, sort_keys=True))
        wazuh_alert['rule']['groups'].append("wazuh")
        #custom_fields = {   "wazuh_manager": wazuh_alert["manager"]["name"],
        #                    "wazuh_agent": wazuh_alert["agent"]["name"],
        #                    "alert_timestamp": wazuh_alert["timestamp"]}
        # To use custom fields, make sure you have them defined at the organization level. Then add the dict key and value: <"customFields": custom_fields>
        # Documentation: https://docs.thehive-project.org/thehive/user-guides/administrators/custom-fields/
        alert = {   "title": wazuh_alert['rule']['description'],
                    "description": description,
                    "type": "external",
                    "source": wazuh_alert['manager']['name'],
                    "sourceRef": "id: {}".format(wazuh_alert['id']),
                    "tags": wazuh_alert['rule']['groups'],
                    "severity": severity,
                    "tlp": severity - 1} #,
        #            "customFields": custom_fields}
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
        result = requests.post(url, data=data, headers=headers, verify=False)
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
