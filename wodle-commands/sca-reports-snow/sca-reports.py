#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# January 17, 2022.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os, sys
import logging
import requests
import json
import yaml
import re
import argparse
import warnings
# Disable insecure https warnings (for self-signed SSL certificates)
warnings.simplefilter("ignore")

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
        request_result = requests.get(WAZUH_API + "/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=False)
        if request_result.status_code == 200:
            TOKEN = json.loads(request_result.content.decode())['data']['token']
            logging.debug("Wazuh Token obtained: {}".format(TOKEN))
        else:
            raise Exception(request_result.json())
    except Exception as e:
        logging.error("Error obtaining the Token: {}".format(e))
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
            if response.status_code == 401:
                logging.debug("Token expired, requesting new token")
                token = get_token()
                response = requests.get("{}{}".format(url, endpoint), headers=headers, verify=False)
            if response.status_code == 200:
                data = json.loads(response.text)
                logging.debug("Total affected items: {}".format(len(data["data"]['affected_items'])))
            else:
                raise Exception(response.json())
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
        logging.error("Error obtaining data from endpoint: {}".format(e))
        sys.exit(1)

    return items

def create_ticket(agent, sca_result):
    # Create SNOW ticket
    SNOW_HEADERS = {'Content-type': 'application/json'}
    SNOW_PAYLOAD["cmdb_ci"] = agent
    SNOW_PAYLOAD["description"] += "\n".join(sca_result)

    # Make request to SNOW API
    try:
        snow_request = requests.post(SNOW_URL, auth=(SNOW_USER, SNOW_PASS), verify=False, data=json.dumps(SNOW_PAYLOAD), headers=SNOW_HEADERS)
        if snow_request.status_code != 201:
            raise Exception("Code {} - {}".format(snow_request.status_code, snow_request.text))
    except Exception as e:
        logging.error("Error creating the ticket in the SNOW Service: {}. {}".format(SNOW_URL, e))
        sys.exit(1)
    
    return json.loads(snow_request.text)

# Main Workflow
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', type=str, required=True, help='Path to the yaml config file')
    parser.add_argument('-d', '--dry-run', action='store_true', required=False, help="Only print the failed checks, don't create ticket")
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    parser.set_defaults(dry_run=False)
    args = parser.parse_args()

    DEBUG = args.debug
    set_logger("sca-reports", "sca-reports.log")

    logging.info("Starting the SCA Reports Tools")
    # Loading the configuration file
    try:
        cfg_text = open(args.config_file, "r")
        cfg_dict = yaml.safe_load(cfg_text)

        WAZUH_API = cfg_dict['wazuh']['url']
        WAZUH_USER = cfg_dict['wazuh']['username']
        WAZUH_PASS = cfg_dict['wazuh']['password']
        WAZUH_POLICIES = cfg_dict['wazuh']['policy_id']

        SNOW_USER = cfg_dict['snow']['username']
        SNOW_PASS = cfg_dict['snow']['password']
        SNOW_URL = cfg_dict['snow']['url']
        SNOW_PAYLOAD = cfg_dict['snow']['payload']
        logging.info("Configuration file loaded correctly")
    except Exception as e:
        logging.error("Error obtaining settings from config file: {}".format(e))
        sys.exit(1)
    
    # Obtaining de data
    logging.info("Obtaining the data from the Wazuh API")
    TOKEN = get_token()
    act_agents = get_data(WAZUH_API, TOKEN, "/agents?limit=500&offset=0&status=active")
    logging.info("Found {} active agents, analyzing SCA results for them".format(len(act_agents)))
    try:
        report_items = []
        for agent in act_agents:
            agent_data = { "name": agent["name"], "id": agent["id"], "policies": [] }
            for policy in WAZUH_POLICIES:
                fail_checks = get_data(WAZUH_API, TOKEN, "/sca/{}/checks/{}?result=failed".format(agent["id"], policy))
                if len(fail_checks) > 0:
                    logging.info("Reporting {} failed checks from policy {} for agent {}".format(len(fail_checks), policy, agent_data["name"]))
                    policy_data = { "policy_id": policy, "failed_checks": fail_checks }
                    agent_data["policies"].append(policy_data)
                else:
                    logging.warning("{} policy not applieded or no failed checks for agent {}".format(policy, agent_data["name"]))
            
            report_items.append(agent_data)
        logging.info("Data collected for {} Agents".format(len(report_items)))
    except Exception as e:
        logging.error("Error collecting data from SCA for the active agents: {}".format(e))
        sys.exit(1)
    
    #Building the Report
    for item in report_items:
        header = "SCA Failed checks for agent {} - {}\n".format(item["id"], item["name"])
        txt_block = ""
        for pol in item["policies"]:
            txt_block += "Failed checks for policy: {}\n".format(pol["policy_id"])
            for chk in pol["failed_checks"]:
                txt_block += "{} - {}\n".format(chk["id"], chk["title"])
            txt_block += "\n"
        if len(item["policies"]) > 0:
            logging.info("Text block generated for agent {}".format(item["name"]))
            if args.dry_run:
                print(header)
                print(txt_block)
            else:
                resp = create_ticket(item["name"], txt_block)
                logging.info("SNOW Ticket created. Response: {}".format(resp["result"]["number"]))
    
    logging.info("SCA Reports tool finished successfully")

        
