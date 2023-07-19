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

################################################## Global variables ##################################################

# Proxy Configuration
#proxy = "http://YOUR_PROXY:8080"
#os.environ['http_proxy'] = proxy
#os.environ['HTTP_PROXY'] = proxy
#os.environ['https_proxy'] = proxy
#os.environ['HTTPS_PROXY'] = proxy

# Integration Identifier
int_id = "microsoft-defender"

# Microsoft resource
resource = "https://api.securitycenter.microsoft.com"

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
    string = '1:microsoft_defender_api:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Perform HTTP request
def make_request(method, url, headers, data=None):
    try:
        response = requests.request(method, url, headers=headers, data=data)
        logging.debug("Making the request: {}".format(data))
    # If the request succeed
        if response.status_code >= 200 and response.status_code < 210:
            return response
        else:
            resp_dict = json.loads(response.text)
            raise Exception("Code {} - {}".format(response.status_code, resp_dict["error_description"]))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while contacting Microsoft: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

# Obtain a token for accessing the Windows Defender API
def obtain_access_token(tenantId, clientId, clientSecret):
    # Add header and payload
    headers = {'Content-Type':'application/x-www-form-urlencoded'}
    payload = 'client_id={}&scope={}/.default&grant_type=client_credentials&client_secret={}'.format(clientId, resource, clientSecret)

    # Request token
    response = make_request("POST", "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(tenantId), headers=headers, data=payload)
    logging.info("Microsoft token was successfully fetched.")

    return json.loads(response.text)['access_token']

# Perform an API request to Microsoft Defender management API
def make_api_request(method, url, token):
    # Create a valid header using the token
    headers = {'Content-Type':'application/json', 'Authorization':'Bearer {0}'.format(token)}

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
    parser = argparse.ArgumentParser(description='Wazuh - Microsoft Defender Security information.')
    parser.add_argument('--days', metavar='days', type=int, required = True, help='How many days to fetch activity logs.')
    parser.add_argument('--tenantId', metavar='tenantId', type=str, required = True, help='Application tenant ID.')
    parser.add_argument('--clientId', metavar='clientId', type=str, required = True, help='Application client ID.')
    parser.add_argument('--clientSecret', metavar='clientSecret', type=str, required = True, help='Client secret.')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()
    defender_url = "{}/api/alerts".format(resource)
 
    # Start logging config
    DEBUG = args.debug
    logfile = os.path.join(logfolder, "{}.log".format(int_id))
    set_logger(int_id, logfile)

    logging.info("------- Starting the Defender Integration Script -------")
    logging.info("Parameters loaded successfully")

    if os.path.isfile('defender-last-id') and os.stat('defender-last-id').st_size != 0:
        prev_file = open('defender-last-id', "r")
        prev_time = dateutil.parser.isoparse(prev_file.read())
        logging.debug("Last date file loaded successfully")
    else:
        prev_time = datetime.today() - timedelta(days=args.days)
        logging.debug("No Last date file found, calculated starting date")
    logging.info("First event date calculated")

    try:
        # Obtain access token
        token = obtain_access_token(args.tenantId, args.clientId, args.clientSecret)
        logging.debug("Microsoft Token obtained successfully")
        data = make_api_request("GET", defender_url, token)
        logging.info("Microsoft Defender logs retrieved")
        data_sorted = sorted(data["value"], key=lambda d: d['alertCreationTime']) 
        cant = 0
        logging.info("Processing events from date: {}".format(prev_time))
        for event in data_sorted:
            last_time = event["alertCreationTime"]
            event_time = dateutil.parser.isoparse(last_time)
            if event_time.replace(tzinfo=None) > prev_time.replace(tzinfo=None):
                event = { int_id: event, "integration": int_id }
                json_event = json.dumps(event)
                logging.debug("Sending event: {}".format(json_event))
                send_event(json_event)
                cant += 1
        logging.info("Finished processing events. {} events sent to Wazuh Manager".format(cant))
        if cant > 0:
            last_file = open('defender-last-id', "w")
            last_file.write(last_time)
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while processing Microsoft Defender Security alerts: [{}] {}".format(exc[2].tb_lineno, e))