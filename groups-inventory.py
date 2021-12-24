#!/var/ossec/framework/python/bin/python3
 
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import requests, urllib3
import sys
import json
import logging, os
import argparse
from socket import socket, AF_UNIX, SOCK_DGRAM

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
manager_ip = "localhost"
socketAddr = '/var/ossec/queue/sockets/queue'

# Send message to socket
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:groups-inventory:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Configuring a logger for the script.
def set_logger(name, logfile=None):
    hostname = os.uname()[1]

    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)

    logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

# Function to get the Wazuh API Token
def get_token(user="wazuh", passw="wazuh"):
    logging.info("Obtaining the Wazuh API token")
    hook_url = "https://"+manager_ip+":55000/security/user/authenticate?raw=true"
    try:
        response = requests.get(hook_url, auth=(user, passw), verify=False)
        return response.text
    except Exception as e:
        logging.error("Error getting the token. Details: "+str(e))
        sys.exit(1)

# Function to get the Agents in a Group
def get_groups(token):
    logging.info("Getting the list of groups")
    hook_url = "https://"+manager_ip+":55000/groups"
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer '+token}, verify=False)
        dict_out = json.loads(response.text)
        return dict_out
    except Exception as e:
        logging.error("Error getting the list of groups. Details: {}".format(str(e)))
        sys.exit(1)

# Function to get the Agents in a Group
def get_agents(token, grp_id):
    logging.info("Getting the list of agents in the group: "+grp_id)
    hook_url = "https://"+manager_ip+":55000/groups/"+grp_id+"/agents"
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer '+token}, verify=False)
        dict_out = json.loads(response.text)
        return dict_out
    except Exception as e:
        logging.error("Error getting the list of agents for the group {}. Details: {}".format(grp_id,str(e)))
        sys.exit(1)

# Function to get specific syscollector information for an agent
def get_inventory(token, agent_id, endpoint):
    logging.info("Querying the syscollector for the agent's inventory. Agent id: "+agent_id+". Endpoint: "+endpoint)
    hook_url = "https://"+manager_ip+":55000/syscollector/"+agent_id+"/"+endpoint
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer '+token}, verify=False)
        dict_out = json.loads(response.text)
        return dict_out
    except Exception as e:
        logging.error("Error getting the inventory information for the agent {}. Details: {}".format(agent_id,str(e)))
        sys.exit(1)

if __name__ == "__main__":
    set_logger("groups-inventory")
    # Parsing arguments
    parser = argparse.ArgumentParser(prog="groups-inventory.py", description='Get inventory information from agents and inject it in Wazuh as an alert.')
    parser.add_argument('--group', nargs='+', help='Group name to query, use ALL for all the groups')
    parser.add_argument('--endpoint', nargs='+', help='Specific syscollector endpoint to query. Use ALL for all the endpoints')
    args = parser.parse_args()
    if not (args.group and args.endpoint):
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Parsing the groups
    groups = args.group
    api_token = get_token("wazuh", "wazuh")
    dict_grp = get_groups(api_token)
    tmp_grp = []
    for item in dict_grp["data"]["affected_items"]:
        tmp_grp.append(item["name"])
    if args.group[0] == "ALL":
        groups = tmp_grp
    else:
        for item in groups:
            if item not in tmp_grp:
                logging.warning("This group does not exists ignoring: "+item)
                groups.remove(item)
    if len(groups) == 0:
        logging.error("No valid groups were passed. Please specify existent groups.")
        sys.exit(1)

    # Parsing the endpoints
    avail_endp = ['hardware', 'hotfixes', 'netaddr', 'netiface', 'netproto', 'os', 'packages', 'ports', 'processes']
    endpoints = args.endpoint
    if args.endpoint[0] == "ALL":
        endpoints = avail_endp
    else:
        for endpt in endpoints:
            if endpt not in avail_endp:
                logging.warning("This endpoint is not available ignoring: "+endpt)
                endpoints.remove(endpt)
    if len(endpoints) == 0:
        logging.error("No valid endpoints specified. Please specify one of them: "+str(avail_endp))
        sys.exit(1)

    # Main Program
    logging.info("Working with the Inventory information")
    for group_name in groups:
        agents = get_agents(api_token, group_name)
        for agent in agents["data"]["affected_items"]:
            for end_itm in endpoints:
                inventory = get_inventory(api_token, agent["id"], end_itm)
                for itm in inventory["data"]["affected_items"]:
                    tmp = {}
                    tmp["inventory"] = {}
                    itm["group"] = group_name
                    itm["endpoint"] = end_itm
                    itm["agent_name"] = agent["name"]
                    itm["agent_ip"] = agent["ip"]
                    itm["agent_version"] = agent["version"]
                    tmp["inventory"] = itm
                    json_msg = json.dumps(tmp, default=str)
                    send_event(json_msg)
    logging.info("Finished getting the inventory for the groups of agents")