#!/bin/python3

import os, time, re
import json, yaml
import sys
import logging
import requests
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

################################################## Global variables ##################################################

log_file = "thehive-cases.log" #"/var/ossec/logs/thehive-cases.log"
cdblist_path = "." #"/var/ossec/etc/lists"

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

def get_token():
    # Get Wazuh JWT token
    logging.debug("Obtaining Wazuh Token")
    try:
        request_result = requests.get(WAZUH_API+"/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=False)
        if request_result.status_code == 200:
            TOKEN = json.loads(request_result.content.decode())['data']['token']
            logging.debug("Wazuh Token obtained: {}".format(TOKEN))
        else:
            raise Exception("Code [{}] - {}".format(request_result.status_code, request_result.json()))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining the Token: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    
    return TOKEN

#Obtain data from the API Endpoint
def get_data(url, token, endpoint):
    #Get data from Wazuh API Endpoint
    headers = { 'Authorization': 'Bearer {}'.format(token) }
    limit = 500
    offset = 0
    if "limit=" in endpoint:
        limit = int(re.search('limit=(\d+)', endpoint).group(1))
    if "offset=" in endpoint:
        offset = int(re.search('offset=(\d+)', endpoint).group(1))
    finish = False
    items = []
    logging.debug("Obtaining data from endpoint: {}".format(endpoint))
    try:
        while not finish:
            endpoint = re.sub('limit=\d+', 'limit={}'.format(limit), endpoint)
            endpoint = re.sub('offset=\d+', 'offset={}'.format(offset), endpoint)
            response = requests.get("{}{}".format(url, endpoint), headers=headers, verify=False)
            while response.status_code == 429:
                delay = 15
                logging.debug("Too many requests, delaying the request for {} seconds".format(str(delay)))
                time.sleep(15)
                response = requests.get("{}{}".format(url, endpoint), headers=headers, verify=False)
            if response.status_code == 401:
                logging.debug("Token expired, requesting new token")
                token = get_token()
                response = requests.get("{}{}".format(url, endpoint), headers=headers, verify=False)
            if response.status_code == 200:
                data = json.loads(response.text)
                logging.debug("Total affected items: {}".format(len(data["data"]['affected_items'])))
            else:
                raise Exception("[{}] - {}".format(response.status_code, response.json()))
            items += data["data"]['affected_items']
            next_group = limit + offset
            affected = int(data["data"]['total_affected_items'])
            if affected > next_group:
                offset = next_group
                if next_group > affected:
                    limit = affected - offset
            else:
                finish = True
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining data from endpoint: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    return items

# Get the list of excluded agents
def get_exclusions(txt_list):
    arr_cdb = []
    for line in txt_list:
        sep = ":"
        try:
            arr_line = line.strip().split(sep)
            arr_cdb.append(arr_line[0])
        except Exception as e:
            logging.warning("Failed to parse the line: {}".format(line))
            continue
    return arr_cdb

# Send the case to TheHive server
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
    return json.loads(result.text)

# Main Workflow
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', type=str, required=True, help='Path to the yaml config file')
    parser.add_argument('-k', '--checks', nargs='+', help='`failed` or `not-applicable` are allowed')
    parser.add_argument('-d', '--dry-run', action='store_true', required=False, help="Only print the failed checks, don't create ticket")
    parser.add_argument('-l', '--cdblist', help='Name of the cdb list containing the excluded hostnames')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    parser.set_defaults(dry_run=False)
    args = parser.parse_args()

    chk_list = [x.lower() for x in args.checks]
    DEBUG = args.debug
    set_logger("sca-reports", log_file)

    logging.info("Starting the SCA Reports Tools")
    # Loading the configuration file
    try:
        cfg_text = open(args.config_file, "r")
        cfg_dict = yaml.safe_load(cfg_text)

        WAZUH_API = cfg_dict['wazuh']['url']
        WAZUH_USER = cfg_dict['wazuh']['username']
        WAZUH_PASS = cfg_dict['wazuh']['password']
        WAZUH_POLICIES = cfg_dict['wazuh']['policy_id']

        TH_KEY = cfg_dict['thehive']['api_key']
        TH_URL = cfg_dict['thehive']['url']
        logging.info("Configuration file loaded correctly")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining settings from config file: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    # Obtaining the data
    logging.info("Obtaining the data from the Wazuh API")
    TOKEN = get_token()
    act_agents = get_data(WAZUH_API, TOKEN, "/agents?limit=500&offset=0&status=active")
    logging.info("Found {} active agents, analyzing SCA results for them".format(len(act_agents)))
    if args.cdblist:
        cdb_file = open(os.path.join(cdblist_path,args.cdblist), "r")
        cdb_list = cdb_file.readlines()
        exclusions = get_exclusions(cdb_list)
        logging.info("Excluding {} agents from the report".format(len(exclusions)))
        for agent in act_agents:
            if agent["name"] in exclusions:
                act_agents.remove(agent)
    logging.info("{} will be analyzed".format(len(act_agents)))
    try:
        report_items = []
        for agent in act_agents:
            agent_data = { "name": agent["name"], "id": agent["id"], "policies": [] }
            for policy in WAZUH_POLICIES:
                policy_data = {}
                if "failed" in chk_list:
                    fail_checks = get_data(WAZUH_API, TOKEN, "/sca/{}/checks/{}?result=failed".format(agent["id"], policy))
                    if len(fail_checks) > 0:
                        logging.info("Reporting {} failed checks from policy {} for agent {}".format(len(fail_checks), policy, agent_data["name"]))
                        policy_data = { "policy_id": policy }
                        policy_data["failed_checks"] = fail_checks
                    else:
                        logging.debug("No failed checks in policy {} for agent {}".format(policy, agent_data["name"]))
                if "not-applicable" in chk_list:
                    na_checks = get_data(WAZUH_API, TOKEN, "/sca/{}/checks/{}?status=Not applicable".format(agent["id"], policy))
                    if len(na_checks) > 0:
                        logging.info("Reporting {} Not-Applicable checks from policy {} for agent {}".format(len(na_checks), policy, agent_data["name"]))
                        policy_data = { "policy_id": policy }
                        policy_data["NA_checks"] = na_checks
                    else:
                        logging.debug("No Not-Applicable checks in policy {} for agent {}".format(policy, agent_data["name"]))
                if policy_data != {}:
                    agent_data["policies"].append(policy_data)
            report_items.append(agent_data)
        logging.info("Data collected for {} Agents".format(len(report_items)))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error collecting data from SCA for the active agents: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    #Building the Report
    for item in report_items:
        header = "SCA Report for agent {} - {}\n".format(item["id"], item["name"])
        txt_block = ""
        for pol in item["policies"]:
            if "failed" in chk_list:
                txt_block += "## Failed checks for policy: **{}**\r\n".format(pol["policy_id"])
                if "failed_checks" in pol:
                    for chk in pol["failed_checks"]:
                        txt_block += "- **{}:** {}\r\n".format(chk["id"], chk["title"])
                    txt_block += "\r\n"
                else:
                    txt_block += "> No failed checks for this agent\r\n"
            if "not-applicable" in chk_list:
                txt_block += "## Not-Applicable checks for policy: **{}**\r\n".format(pol["policy_id"])
                if "NA_checks" in pol:
                    for chk in pol["NA_checks"]:
                        txt_block += "- **{}:** {}\r\n".format(chk["id"], chk["title"])
                    txt_block += "\r\n"
                else:
                    txt_block += "> No Not-Applicable checks for this agent\r\n"
        if len(item["policies"]) > 0:
            logging.info("Text block generated for agent {}".format(item["name"]))
            if args.dry_run:
                print(header)
                print(txt_block)
            else:
                payload = {"title": header, "description": txt_block}
                resp = send_thehive(TH_URL, TH_KEY, payload)
                logging.info("TheHive case Number: {} created, ID: {}".format(resp["number"], resp["_id"]))
    
    logging.info("SCA Reports tool finished successfully")