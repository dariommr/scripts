#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os, sys
import json
import requests
import logging
import dateutil.parser
from datetime import timedelta, datetime
from socket import socket, AF_UNIX, SOCK_DGRAM
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable insecure https warnings (for self-signed SSL certificates)

################################################## Global variables ##################################################

# Proxy Configuration
#proxy = "http://YOUR_PROXY:8080"
#os.environ['http_proxy'] = proxy
#os.environ['HTTP_PROXY'] = proxy
#os.environ['https_proxy'] = proxy
#os.environ['HTTPS_PROXY'] = proxy

# Integration Identifier
int_id = "github-ent"

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Location of the log file. Set it in <None> if no need for logfile
logfolder = "/var/ossec/logs"

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

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:github_ent_api:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Perform HTTP request
def make_request(method, url, headers, data=None):
    try:
        response = requests.request(method, url, headers=headers, data=data, verify=False)
        logging.debug("Making the request: {}".format(data))
    # If the request succeed
        if response.status_code >= 200 and response.status_code < 210:
            return response
        else:
            resp_dict = json.loads(response.text)
            raise Exception("Code {} - {}".format(response.status_code, resp_dict["message"]))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while contacting the server: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

# Perform an API request to Microsoft Defender management API
def make_api_request(method, url, token):
    # Create a valid header using the token
    headers = {'Authorization':'Bearer {0}'.format(token)}

    # Make API request
    response = make_request(method, url, headers=headers)

    # If this is a POST request just return
    if (method == "POST"):
        return None

    json_data = json.loads(response.text)

    return json_data

################################################## Main workflow ##################################################

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description='Wazuh - GitHub Enterprise Audit Logs.')
    parser.add_argument('--server', metavar='server', required = True, help='IP Address (or IP-ADDRESS:PORT) of the Github Server.')
    parser.add_argument('--days', metavar='days', type=int, required = True, help='How many days to fetch activity logs.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--ent', action='store_true', help='Querying the enterprise audit logs.')
    group.add_argument('--org', action='store_true', help='Querying the Organization audit logs.')
    parser.add_argument('--name', metavar='tenantId', type=str, required = True, help='Name of the Enterprise or Organization.')
    parser.add_argument('--token', metavar='clientId', type=str, required = True, help='Github personal token.')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()
    # Microsoft resource
    resource = "https://{}/api/v3".format(args.server)
    token = args.token
 
    # Start logging config
    DEBUG = args.debug
    logfile = os.path.join(logfolder, "{}.log".format(int_id))
    set_logger(int_id, logfile)

    logging.info("------- Starting the GitHub Integration Script -------")
    logging.info("Parameters loaded successfully")

    if args.ent:
        endpoint = "enterprises"
    if args.org:
        endpoint = "orgs"
    endpoint_url = "{}/{}/{}/audit-log".format(resource, endpoint, args.name)

    last_id_file = "{}-last-id".format(int_id)
    if os.path.isfile(last_id_file) and os.stat(last_id_file).st_size != 0:
        prev_file = open(last_id_file, "r")
        prev_dict = json.loads(prev_file.read())
        logging.debug("Last date file loaded successfully")
        prev_time = int(prev_dict[endpoint])
    else:
        prev_dict = { "enterprises": "0", "orgs": "0"}
        prev_dtime = datetime.today() - timedelta(days=args.days)
        prev_time = prev_dtime.timestamp()
        prev_dict[endpoint] = prev_time
        logging.debug("No Last date file found, calculated starting date")
    logging.info("First event date calculated")

    try:
        data = make_api_request("GET", endpoint_url, token)
        logging.info("GitHub Audit logs retrieved")
        data_sorted = sorted(data, key=lambda d: d['created_at']) 
        cant = 0
        show_prev, ms = divmod(prev_time, 1000)
        logging.info("Processing events from date: {}".format(datetime.fromtimestamp(show_prev)))
        for event in data_sorted:
            last_time = event["created_at"]
            event_time = last_time
            if event_time > prev_time:
                event["endpoint"] = endpoint
                event = { int_id: event }
                event["integration"] = int_id
                json_event = json.dumps(event)
                logging.debug("Sending event: {}".format(json_event))
                send_event(json_event)
                cant += 1
        logging.info("Finished processing events. {} events sent to Wazuh Manager".format(cant))
        prev_dict[endpoint] = last_time
        if cant > 0:
            last_file = open(last_id_file, "w")
            last_file.write(json.dumps(prev_dict))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while processing GitHub Enterprise Audit Log: [{}] {}".format(exc[2].tb_lineno, e))
