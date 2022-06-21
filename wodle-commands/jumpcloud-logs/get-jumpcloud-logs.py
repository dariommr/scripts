# Perform HTTP request
import requests
import logging
import os, sys
import json
import argparse
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

# JumpCloud URL
jc_url = "https://api.jumpcloud.com/insights/directory/v1/events"

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Location of the log file. Set it in <None> if no need for logfile
logfile = "jumpcloud-api.log"

################################################## Common functions ##################################################

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:jumpcloud_api:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

def make_request(method, url, headers, data=None):
    response = requests.request(method, url, headers=headers, data=data)

    # If the request succeed 
    if response.status_code >= 200 and response.status_code < 210:
        return response
    if method == "POST" and response.status_code == 400:
        return response
    else:
        raise Exception('Request ', method, ' ', url, ' failed with ', response.status_code, ' - ', response.text)

# Perform an API request to JumpCloud API
def make_api_request(method, url, api_key, data):
    # Create a valid header using the token
    headers = {'Content-Type':'application/json', 'x-api-key':api_key}

    # Make API request
    response = make_request(method, url, headers=headers, data=data)

    json_data = json.loads(response.text)

    return json_data

################################################## Main workflow ##################################################

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description='Wazuh - JumpCloud Integration Script.')
    parser.add_argument('--days', metavar='days', type=int, required = True, help='How many days to fetch activity logs.')
    parser.add_argument('--apikey', metavar='apikey', type=str, required = True, help='Jumpcloud user API Key.')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()
 
    # Start logging config
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S") #, filename=logfile)
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S") #, filename=logfile)

    logging.info("------- Starting the JumpCloud Integration Script -------")
    logging.info("Parameters loaded successfully")

    if os.path.isfile('jumpcloud-last-id'):
        prev_file = open('jumpcloud-last-id', "r")
        prev_time = dateutil.parser.isoparse(prev_file.read())
        logging.debug("Last date file loaded successfully")
    else:
        prev_time = datetime.today() - timedelta(days=args.days)
        logging.debug("No Last date file found, calculated starting date")
    logging.info("First event date calculated")
    req_data = {"service": ["all"], "start_time": prev_time.strftime("%Y-%m-%dT%H:%M:%SZ")}

    try:
        events = make_api_request("POST",jc_url,args.apikey,json.dumps(req_data))
        logging.info("JumpCloud logs retrieved")
        data_sorted = sorted(events, key=lambda d: d['timestamp']) 
        cant = 0
        logging.info("Sending events to Wazuh Manager from date: {}".format(prev_time))
        for event in data_sorted:
            last_time = event["timestamp"]
            event_time = dateutil.parser.isoparse(last_time)
            if event_time.replace(tzinfo=None) > prev_time.replace(tzinfo=None):
                event = {'jumpcloud': event}
                json_event = json.dumps(event)
                logging.debug("Sending event: {}".format(json_event))
                send_event(json_event)
                cant += 1
        logging.info("Finished collecting events. {} events sent to Wazuh Manager".format(cant))
        last_file = open('jumpcloud-last-id', "w")
        last_file.write(last_time)
        last_file.close()
    except Exception as e:
        logging.error("Error while retrieving JumpCloud logs: {}.".format(e))