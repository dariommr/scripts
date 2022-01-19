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
from datetime import timedelta, datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

################################################## Global variables ##################################################

# Proxy Configuration
#proxy = "http://YOUR_PROXY:8080"
#os.environ['http_proxy'] = proxy
#os.environ['HTTP_PROXY'] = proxy
#os.environ['https_proxy'] = proxy
#os.environ['HTTPS_PROXY'] = proxy

# Microsoft resource
resource = "https://api.securitycenter.microsoft.com"

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Location of the log file. Set it in <None> if no need for logfile
logfile = "/var/ossec/logs/win-defender-api.log"

################################################## Common functions ##################################################

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:win_defender_api:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Perform HTTP request
def make_request(method, url, headers, data=None):
    response = requests.request(method, url, headers=headers, data=data)

    # If the request succeed 
    if response.status_code >= 200 and response.status_code < 210:
        return response
    if method == "POST" and response.status_code == 400:
        return response
    else:
        raise Exception('Request ', method, ' ', url, ' failed with ', response.status_code, ' - ', response.text)

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
    defender_url = "https://api.securitycenter.microsoft.com/api/alerts"
 
    # Start logging config
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    logging.info("------- Starting the Defender Integration Script -------")
    logging.info("Parameters loaded successfully")

    if os.path.isfile('defender-last-id'):
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
        logging.info("Sending events to Wazuh Manager from date: {}".format(prev_time))
        for event in data_sorted:
            last_time = event["alertCreationTime"]
            event_time = dateutil.parser.isoparse(last_time)
            if event_time.replace(tzinfo=None) > prev_time.replace(tzinfo=None):
                json_event = json.dumps(event)
                logging.debug("Sending event: {}".format(json_event))
                send_event(json_event)
                cant += 1
        logging.info("Finished collecting events. {} events sent to Wazuh Manager".format(cant))
        last_file = open('defender-last-id', "w")
        last_file.write(last_time)
    except Exception as e:
        logging.error("Error while retrieving Defender Security logs: {}.".format(e))
