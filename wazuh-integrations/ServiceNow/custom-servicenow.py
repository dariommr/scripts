#!/bin/python3

import os
import pwd, grp, stat
import json
import sys
from datetime import datetime
import logging
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

################################################## Global variables ##################################################

alert_file = open(sys.argv[1], encoding='latin-1')
user = sys.argv[2].split(":")[0]
password = sys.argv[2].split(":")[1]
hook_url = sys.argv[3]          #https://<domain>/api/now/table
alert_json = json.loads(alert_file.read())
alert_file.close()
DEBUG = False

################################################## Common functions ##################################################

#Read CDB list files and convert them into filters into a dictionary format
def convert_filter(txt_list):
    filter_arr = []
    filter_arr.append({})
    for line in txt_list:
        sep = ":"
        try:
            arr_line = line.strip().split(sep)
            entry = { arr_line[0]: {} }
            properties = sep.join(arr_line[1:])
            arr_prop = properties.split(",")
            entry[arr_line[0]] = { "Description": arr_prop[0].replace("|", ":"), "inc_or_vuln": arr_prop[1], "category": arr_prop[2] }
            filter_arr[0].update(entry)
        except Exception as e:
            exc = sys.exc_info()
            logging.debug("Error converting the line into JSON: [{}] - Reason: [{}]: {}".format(line, exc[2].tb_lineno, e))
            continue
    return filter_arr

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

def createSIR(user, password, shortdesc, cmdb_ci, description, additional_comments, category, priority, risk):
    proxyDict = {
        "http" : "",
        "https" : "",
    }
    # Insert call to SN API here and grab sysid from response body
    state = "1"
    url = hook_url+"/sn_si_incident"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {}
    try:
        payload["short_description"] = shortdesc
        payload["state"] = state
        payload["cmdb_ci"] = cmdb_ci
        payload["comments"] = additional_comments
        payload["description"] = description
        payload["category"] = category
        payload["priority"] = priority
        payload["risk_score"] = risk
        payload["risk_score_override"] = "true"
        payload["contact_type"] = "siem"
        r = requests.post(
            url, data=json.dumps(payload), headers=headers, auth=(user, password), verify=True, proxies=proxyDict
        )
        if r.status_code >= 200 and r.status_code <= 299:
            logging.debug("Ticket Created with data {} in the service {} and a response: {}".format(payload, url, r.text))
        else:
            raise Exception("Response: {} {}".format(r.status_code, r.text))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error Creating SIR: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    return r

def createVULN(user, password, cmdb_ci, cve, additional_comments):
    proxyDict = {
        "http" : "",
        "https" : "",
    }
    # Insert call to SN API here and grab sysid from response body
    url = hook_url+"/sn_vul_vulnerable_item"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {}
    try:
        payload["cmdb_ci"] = cmdb_ci
        payload["comments"] = additional_comments
        payload["vulnerability"] = cve
        r = requests.post(
            url, data=json.dumps(payload), headers=headers, auth=(user, password), verify=True, proxies=proxyDict
        )
        if r.status_code >= 200 and r.status_code <= 299:
            logging.debug("Ticket Created with data {} in the service {} and a response: {}".format(payload, url, r.text))
        else:
            raise Exception("Response: {} {}".format(r.status_code, r.text))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error Creating VULN: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    return r

# Check if the filter file exists, if not it creates the file
def manageFile(filter_file):
    if not os.path.exists(filter_file):
        open(filter_file,'a').close()
        uid = pwd.getpwnam("ossec").pw_uid
        gid = grp.getgrnam("ossec").gr_gid
        os.chown(filter_file, uid, gid)
        os.chmod(filter_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

################################################## Main workflow ##################################################

if __name__ == "__main__":
    set_logger("snow-integration", "/var/ossec/logs/integrations.log")

    logging.info("SNOW integration started")
    try:
        logging.info("Loading filters")
        manageFile("/var/ossec/etc/lists/filter1")
        filter1_file = open("/var/ossec/etc/lists/filter1", "r")
        manageFile("/var/ossec/etc/lists/filter2")
        filter2_file = open("/var/ossec/etc/lists/filter2", "r")
        filter1_json = convert_filter(filter1_file.readlines())
        filter2_json = convert_filter(filter2_file.readlines())
        filter1_file.close()
        filter2_file.close()
        logging.debug("Filters loaded successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error loading the filters: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    
    try:
        logging.info("Loading alert parameters")
        alert_level = alert_json["rule"]["level"]
        description = alert_json["rule"]["description"]
        cmdb_ci = alert_json["agent"]["name"]
        description = description + " on " + cmdb_ci
        alert_id = alert_json["rule"]["id"]
        alert_groups = alert_json["rule"]["groups"]
        if "data" in alert_json:
            additional_comments = alert_json["data"]
        else:
            additional_comments = "No data for this alert"
            logging.warning(additional_comments)
        logging.debug("Alert parameters loaded successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error loading the alert parameters: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    #priority and risks
    priority = ''
    risk = ''
    try:
        if alert_level >= 6 and alert_level <= 8:
            priority = '4 - Low'
            risk = '40'

        if alert_level >= 9 and alert_level <= 11:
            priority = '3 - Moderate'
            risk = '50'

        if alert_level >= 12 and alert_level <= 13:
            priority = '2 - High'
            risk = '75'

        if alert_level >= 14 and alert_level <= 15:
            priority = '1 - Critical'
            risk = '100'
        logging.debug("Priority and risk set successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while setting Priority and risk: [{}] {}".format(exc[2].tb_lineno, e))


    # recuperation des filtres

    date_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    present_in_filter1 = False
    present_in_filter2 = False
    present_group = ""

    logging.info("Analyzing the alert {} with groups {}".format(alert_id, alert_groups))
    for group in alert_groups:
        for filter_group in filter1_json:
            if group in filter_group:
                if int(alert_level) >= filter_group[group]["level"]:
                    present_in_filter1 = True
                    present_group = group
                    logging.debug("Alert present in filter1, Group: {}".format(group))
    if present_in_filter1 is False:
        for filter2_group in filter2_json:
            if alert_id in filter2_group:
                present_in_filter2 = True
                logging.debug("Alert present in filter2")
    if not present_in_filter1 and not present_in_filter2:
        logging.info("The alert {} is not present on any filter, discarding".format(alert_id))
        sys.exit(0)

    try:
        logging.debug("Preparing the payload")
        if present_in_filter1 is True or present_in_filter2 is True:
            if present_in_filter1 is True:
                logging.info("Present in filter1, analyzing")
                if filter1_json[0][group]["inc_or_vuln"] == "inc":
                    category = "No Incident"
                    createSIR(
                        user,
                        password,
                        description,
                        cmdb_ci,
                        description,
                        additional_comments,
                        category,
                        priority,
                        risk
                    )
                    logging.info("SIR Created successfully")
                elif filter1_json[0][group]["inc_or_vuln"] == "vuln":
                    cve = alert_json["data"]["cve"]
                    createVULN(user, password, cmdb_ci, cve, additional_comments)
                    logging.info("VULN Created successfully")
                else:
                    logging.warning("Filter1 does not contain inc or vuln categories")
                    sys.exit(1)
            if present_in_filter2 is True:
                logging.info("Present in filter2, analyzing")
                if filter2_json[0][alert_id]["inc_or_vuln"] == "inc":
                    category = filter2_json[0][alert_id]["category"]
                    createSIR(
                        user,
                        password,
                        description,
                        cmdb_ci,
                        description,
                        additional_comments,
                        category,
                        priority,
                        risk
                    )
                    logging.info("SIR Created successfully")
                elif filter2_json[0][alert_id]["inc_or_vuln"] == "vuln":
                    cve = alert_json["data"]["vulnerability"]["cve"]
                    createVULN(user, password, cmdb_ci, cve, additional_comments)
                    logging.info("VULN Created successfully")
                else:
                    logging.warning("Filter1 does not contain inc or vuln categories")
                    sys.exit(1)
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error creating the ticket request: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)