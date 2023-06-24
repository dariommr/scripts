#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2023, Wazuh Inc.
# January 20, 2023.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os, sys
import logging
import requests
import json, yaml
import argparse
from datetime import datetime, date, timedelta
import warnings
warnings.filterwarnings("ignore")

################################################## Global variables ##################################################
DEBUG = False
log_file = "/var/log/remove_old_indices.log"
INDEX_PATTERN = "wazuh-alerts-"

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

def get_indices(pattern):
    hook_url = "https://"+IDX_IP+"/_cat/indices/"+pattern+"*?s=index&h=i"
    idx_list = requests.get(hook_url, auth=(IDX_USER, IDX_PASSW), verify=False)
    if idx_list.text.startswith("{"):
        error_dict = json.loads(idx_list.text)
        raise Exception(error_dict["error"])
    else:
        result = idx_list.text
        res_array = [ a for a in result.split("\n") if a != "" ]
    return res_array

def delete_indices(indices, days):
    before = date.today() - timedelta(days)
    deletables = []
    for idx in indices:
        str_date = idx.split("-")[3]
        idx_date = datetime.strptime(str_date, "%Y.%m.%d").date()
        if idx_date < before:
            deletables.append(idx)
    del_result = [0, 0]
    for item in deletables:
        hook_url = "https://"+IDX_IP+"/"+item
        result = requests.delete(hook_url, auth=(IDX_USER, IDX_PASSW), verify=False)
        result_dict = json.loads(result.text)
        if "acknowledged" in result_dict.keys():
            if result_dict["acknowledged"] == True:
                logging.debug("Index deleted: {}".format(item))
                del_result[0] += 1
            else:
                logging.warning("Culdn't delete index: {}".format(item))
                del_result[1] += 1
        if "error" in result_dict.keys():
            logging.error("Culdn't delete index: {}. Error: {}".format(item, result_dict["error"]["reason"]))
            del_result[1] += 1
    return del_result


################################################## Main Program #####################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', type=str, required=True, help='Path to the yaml config file')
    parser.add_argument('-d', '--days', required=True, help="Number of days to query for")
    parser.add_argument('--debug', action='store_true', required=False, help='Enable debug mode logging.')
    parser.add_argument('--dry-run', action='store_true', required=False, help='Show results to screen. Do not store on SQL.')
    args = parser.parse_args()

    DEBUG = args.debug
    set_logger("remove-old-indices", log_file)
    try:
        cfg_text = open(args.config_file, "r")
        cfg_dict = yaml.safe_load(cfg_text)

        IDX_IP = cfg_dict['connection']['wazuh']['indexerIp']
        IDX_USER = cfg_dict['connection']['wazuh']['username']
        IDX_PASSW = cfg_dict['connection']['wazuh']['password']

        logging.debug("All configurations readed from the config file: {}".format(args.config_file))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining settings from config file: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    try:
        logging.info("Obtaining all Indices")
        all_indices = get_indices(INDEX_PATTERN)
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining the indices list: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    try:
        logging.info("Listing {} indices".format(len(all_indices)))
        res = delete_indices(all_indices, int(args.days))
        logging.info("{} Indices deleted. {} Couldn't be deleted".format(res[0], res[1]))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error deleting indices: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)