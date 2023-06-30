#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os, os.path
import json
import requests
import logging
import dateutil.parser
import base64
import time
from requests.auth import HTTPBasicAuth
from datetime import timedelta, datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

################################################## Global variables ##################################################

# Integration Identifier
int_id = "confluence"

# Atlassian resource
resource = "https://rently.atlassian.net/wiki/rest/api/audit"

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Location of the log file. Set it in <None> if no need for logfile
logfolder = "/var/ossec/logs"

################################################## Common functions ##################################################

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:confluence_logs_api:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Perform HTTP request
def make_request(method, url, auth, headers):
    response = requests.request(method, url, headers=headers, auth=auth)

    # If the request succeed 
    if response.status_code >= 200 and response.status_code < 210:
        return response
    else:
        raise Exception('Request ', method, ' ', url, ' failed with ', response.status_code, ' - ', response.text)

# Perform an API request to Atlassian confluence API
def make_api_request(url, token, email):
    # Create a valid header using the token
    headers = { "Accept": "application/json" }

    auth = HTTPBasicAuth(email, token)

    # Make API request
    response = make_request("GET", url, auth, headers=headers)

    json_data = json.loads(response.text)

    return json_data

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description='Wazuh - Confluence Logs Integration Script.')
    parser.add_argument('--hours', metavar='days', type=int, required = True, help='How many hours to fetch activity logs.')
    parser.add_argument('--email', metavar='email', type=str, required = True, help='The Confluence email ID.')
    parser.add_argument('--token', metavar='token', type=str, required = True, help='Confluence user token.')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()

    current_time = str(datetime.utcnow())
    current_time = current_time.replace(" ", "T")
    previous_utc_hour = str(datetime.utcnow() - timedelta(hours=args.hours))
    previous_utc_hour = previous_utc_hour.replace(" ", "T")

    query_url = resource+"?from{}&?to={}".format(previous_utc_hour, current_time)
 
    # Start logging config
    logfile = os.path.join(logfolder, "{}.log".format(int_id))
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    logging.info("------- Starting the Confluence Logs Integration Script -------")
    logging.info("Parameters loaded successfully")

    if os.path.isfile('confluence-last-id'):
        prev_file = open('confluence-last-id', "r")
        epoch_prev = prev_file.read()
        logging.debug("Last date file loaded successfully")
    else:
        prev_time = datetime.today() - timedelta(hours=args.hours)
        epoch_prev = str(prev_time.timestamp()).split(".")[0]
        logging.debug("No Last date file found, calculated starting date")
    logging.info("First event date calculated")

    try:
        # Obtain access token
        confl_token = args.token
        data = make_api_request(query_url, confl_token, args.email)
        logging.info("Confluence logs retrieved: {}".format(data["size"]))
        cant = 0
        logging.info("Sending events to Wazuh Manager from date: {}".format(epoch_prev))
        last_time = data["results"][0]["creationDate"]
        for event in data["results"]:
            event_time = event["creationDate"]
            if event_time > int(epoch_prev):
                event = { int_id: event }
                json_event = json.dumps(event)
                logging.debug("Sending event: {}".format(json_event))
                send_event(json_event)
                cant += 1
        logging.info("Finished collecting events. {} events sent to Wazuh Manager".format(cant))
        last_file = open('confluence-last-id', "w")
        last_file.write(str(last_time))
    except Exception as e:
        logging.error("Error while retrieving Confluence logs: {}.".format(e))