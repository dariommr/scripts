import sys, os
import requests, re
import json, yaml
import time
import logging
import urllib3
import argparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

################################################## Global variables ##################################################

log_file = "vd-thehive.log" #"/var/ossec/logs/vd-thehive.log"

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

# Get Wazuh JWT token
def get_token(url, user, passw):
    logging.debug("Obtaining Wazuh Token")
    try:
        request_result = requests.get(url+"/security/user/authenticate", auth=(user, passw), verify=False)
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

# Agent Report Creation
def agent_report(agent_name):
    vd_agent = get_data(WAZUH_API, jwt_token, "/vulnerability/{}?limit=500&offset=0".format(agent_name))
    if len(vd_agent) == 0:
        report_dict = {"error": True}
    else:
        try:
            vd_table = "## Active Vulnerabilities\r\n| TYPE | NAME | TITLE | CVE |\r\n| --- | --- | --- | --- |\r\n"
            statistics = { "type": {}, "severity": {}, "name": {}, "status": {} }
            for vuln in vd_agent:
                if vuln["type"] in statistics["type"]:
                    statistics["type"][vuln["type"]] += 1
                else:
                    statistics["type"][vuln["type"]] = 1
                if vuln["severity"] in statistics["severity"]:
                    statistics["severity"][vuln["severity"]] += 1
                else:
                    statistics["severity"][vuln["severity"]] = 1
                if vuln["name"] in statistics["name"]:
                    statistics["name"][vuln["name"]] += 1
                else:
                    statistics["name"][vuln["name"]] = 1
                if vuln["status"] in statistics["status"]:
                    statistics["status"][vuln["status"]] += 1
                else:
                    statistics["status"][vuln["status"]] = 1
                if vuln["status"] != "Solved":
                    vd_table += "| {} | {} | {} | {} |\r\n".format(vuln["type"], vuln["name"], vuln["title"], vuln["cve"])
            stats_table = "## Statistics for agent {}\r\n".format(agent)
            for key in statistics:
                if key == "name":
                    section = "**Name** (top 5):\r\n"
                    sorted_dict = sorted(statistics["name"], key=statistics["name"].get, reverse=True)
                    for subkey in sorted_dict[:5]:
                        tmp_str = "- "+subkey+": "+str(statistics[key][subkey])+"\r\n"
                        section += tmp_str
                else:
                    section = "**"+key.capitalize()+"**\r\n"
                    for subkey in statistics[key]:
                        tmp_str = "- "+subkey+": "+str(statistics[key][subkey])+"\r\n"
                        section += tmp_str
                stats_table += section+"\r\n"
            header = "Vulnerability Detector Report for agent {}".format(agent_name)
            report_dict = {"header": header, "statistics": stats_table, "table": vd_table, "error": False}
            logging.info("Report generated for agent {}".format(agent))
        except Exception as e:
            exc = sys.exc_info()
            logging.error("Unable to create report for agent: [{}] {}".format(exc[2].tb_lineno, e))
            sys.exit(1)
    return report_dict

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', type=str, required=True, help='Path to the yaml config file')
    agentids = parser.add_mutually_exclusive_group()
    agentids.add_argument('-g', '--groups', nargs='+', help='Agent groups names separated by space')
    agentids.add_argument('-i', '--ids', nargs='+', help='IDs of the agents')
    agentids.add_argument('--all', action='store_true', required = False, help='All the agents')
    parser.add_argument('-d', '--dry-run', action='store_true', required=False, help="Only print the failed checks, don't create ticket")
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    parser.set_defaults(dry_run=False)
    args = parser.parse_args()

    DEBUG = args.debug
    set_logger("vd-reports", log_file)

    logging.info("Starting the VD Reports Tools")
    # Loading the configuration file
    try:
        cfg_text = open(args.config_file, "r")
        cfg_dict = yaml.safe_load(cfg_text)

        WAZUH_API = cfg_dict['wazuh']['url']
        WAZUH_USER = cfg_dict['wazuh']['username']
        WAZUH_PASS = cfg_dict['wazuh']['password']

        TH_KEY = cfg_dict['thehive']['api_key']
        TH_URL = cfg_dict['thehive']['url']
        #TH_REP = cfg_dict['thehive']['reports']
        logging.info("Configuration file loaded correctly")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining settings from config file: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    # Getting list of agents
    jwt_token = get_token(WAZUH_API, WAZUH_USER, WAZUH_PASS)
    agents_list = []
    
    if args.groups:
        for group in args.groups:
            endp_grp = "/groups/{}/agents?limit=500&offset=0".format(group)
            agts = get_data(WAZUH_API, jwt_token, endp_grp)
            agt_ids = [x["id"] for x in agts]
            agents_list += agt_ids
    if args.ids:
        agents_list = args.ids
    if args.all:
        endp_agt = "/agents?limit=500&offset=0"
        agts = get_data(WAZUH_API, jwt_token, endp_agt)
        agents_list = [x["id"] for x in agts]

    # Obtaining the data
    logging.info("Obtaining the data from the Wazuh API")
    for agent in agents_list:
        agent_rep = agent_report(agent)
        if agent_rep["error"]:
            logging.warning("No vulnerabilities retrieved for agent: {}".format(agent))
        else:
            if args.dry_run:
                print(agent_rep["header"])
                print(agent_rep["statistics"])
            else:
                description = agent_rep["header"] +"\r\n"+ agent_rep["statistics"] + agent_rep["table"]
                payload = {"title": agent_rep["header"], "description": description, "tags": ["wazuh", "vd-report"]}
                resp = send_thehive(TH_URL, TH_KEY, payload)
                logging.info("TheHive case created, Number: {} - ID: {}".format(resp["number"], resp["_id"]))
            