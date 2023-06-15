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
import pyodbc
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

################################################## Global variables ##################################################
DEBUG = False
log_file = "/var/log/wazuh2sql.log"

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

# Retrieve visualization properties from the Wazuh Dashboard
def get_vis(vis_id):
    hook_url = "https://"+DASH_IP+"/api/saved_objects/visualization/"+vis_id
    try:
        result = requests.get(hook_url, auth=(IDX_USER, IDX_PASSW), verify=False)
        data = json.loads(result.text)
        if "error" in data:
            raise Exception("("+str(data["statusCode"])+") "+data["message"])
        else:
            logging.info("Visualization information retrieved successfully")
    except Exception as e:
        logging.error("Failed to retrieve visualization information: {}".format(e))
        sys.exit(1)
    try:
        query_config = json.loads(data["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
        vis_configs = json.loads(data["attributes"]["visState"])
        for refer in data["references"]:
            if refer["type"] == "index-pattern":
                pattern = refer["id"]
        vis_configs["filter"] = []
        if query_config["query"]["query"] != "":
            q_query = { 'multi_match': { 'type': 'best_fields', 'query': query_config["query"]["query"], 'lenient': 'true' } }
            vis_configs["filter"].append(q_query)
        if len(query_config["filter"]) > 0:
            vis_configs["must_not"] = []
            vis_configs["query"] = []
            for item in query_config["filter"]:
                if item["meta"]["type"] == "phrase":
                    it_query = item["query"]
                if item["meta"]["type"] == "phrases":
                    vis_configs["query"] = item["query"]["bool"]
                    it_query = item["query"]
                if item["meta"]["type"] == "exists":
                    it_query = {"exists":{"field":item["meta"]["key"]}}
                if item["meta"]["negate"]:
                    vis_configs["must_not"].append(it_query)
                else:
                    vis_configs["filter"].append(it_query)
    except Exception as e:
        logging.error("Error. The visualization contains not supported configurations: {}".format(e))
        sys.exit(1)
    return vis_configs, pattern

#Function to build the search query from the visualization parameters
def build_aggs(vis_aggs,days):
    def aggs_schema(arr_ids, blocks, metrics):
        aggs = {}
        for k in arr_ids:
            for block in blocks:
                if block["id"] == k:
                    inner_agg = {}
                    inner_agg["terms"] = {}
                    inner_agg["terms"]["field"] = block["params"]["field"]
                    inner_agg["terms"]["order"] = {}
                    for metric in metrics:
                        if block["params"]["orderBy"] == metric["id"]:
                            met = "_"+metric["type"]
                            inner_agg["terms"]["order"][met] = block["params"]["order"]
                    inner_agg["terms"]["size"] = block["params"]["size"]
                    if "include" in block["params"]:
                        inner_agg["terms"]["include"] = block["params"]["include"]
                    if "exclude" in block["params"]:
                        inner_agg["terms"]["exclude"] = block["params"]["exclude"]
            new_arr = arr_ids
            new_arr.remove(k)
            aggs = {"aggs": { k: inner_agg }}
            aggs["aggs"][k].update(aggs_schema(new_arr, blocks, metrics))
        return aggs
    mets = []
    buckets = []
    ids = []
    for item in vis_aggs["aggs"]:
        if item["schema"] == "metric":
            mets.append(item)
        else:
            ids.append(item["id"])
            buckets.append(item)
    aggs_dict = aggs_schema(ids, buckets, mets)
    aggs_dict["size"] = 0
    
    gte = "now-"+days+"d/d"
    srch_range = {"range":{"timestamp":{"gte":gte,"lte":"now/d","format":"strict_date_optional_time"}}}
    tmp_dict = {"query": {"bool": {"filter": [], "must_not": []}}}
    tmp_dict["query"]["bool"]["filter"].append(srch_range)
    if "filter" in vis_aggs:
        tmp_dict["query"]["bool"]["filter"] += vis_aggs["filter"]
    if "must_not" in vis_aggs:
        tmp_dict["query"]["bool"]["must_not"] += vis_aggs["must_not"]
    if "query" in vis_aggs:
        for key in vis_aggs["query"]:
            tmp_dict["query"]["bool"][key] = vis_aggs["query"][key]
    aggs_dict.update(tmp_dict)
    return aggs_dict

#Function to search in Wazuh Indexer
def search(data_dict, pattern):
    hook_url = "https://"+IDX_IP+"/"+pattern+"/_search"
    headers = {'Content-Type': 'application/json'}
    data = json.dumps(data_dict)
    try:
        json_result = requests.get(hook_url, auth=(IDX_USER, IDX_PASSW), verify=False, headers=headers, data=data)
        result = json.loads(json_result.text)
        if "error" in result:
            res_error = result["error"]["caused_by"]
            raise Exception(res_error["type"]+": "+res_error["reason"])
        else:
            return result["aggregations"]
    except Exception as e:
        logging.error("Failed to execute search in Wazuh Indexer: {}".format(e))
        sys.exit(1)

#Converts the aggregations results into a table (array of rows)
def extract_data(in_dict, table=[], key=2, prefix={}):
    if "key" in in_dict.keys():
        prefix[str(key)] = in_dict["key"]
    for bucket in in_dict[str(key)]["buckets"]:
        tmp_list = []
        nkey = key + 1
        if str(nkey) in bucket:
            extract_data(bucket, table, nkey, prefix)
        else:
            for tk in range(3,key+1):
                tmp_list.append(prefix[str(tk)])
            tmp_list.append(bucket["key"])
            tmp_list.append(bucket["doc_count"])
            table.append(tmp_list)
    return table

# Function to get and match the columns with the configurations
def match_columns(vis_aggs):
    vis_met = []
    vis_col = []
    for agg in vis_aggs["aggs"]:
        if agg["schema"] == "bucket":
            vis_col.append(agg["params"]["field"])
        if agg["schema"] == "metric":
            vis_met.append(agg["type"])
    out_cols = []
    for column in vis_col:
        exist = False
        for item in COLUMNS:
            if column in item:
                out_cols.append(item[column])
                exist = True
        if not exist:
            raise Exception("Columns mismatch error. Please review the configuration file")
    for met in vis_met:
        out_cols.append(met)
    out_cols.append("timestamp")
    return out_cols

# Function to take an array and inject it into a SQL database table (the first item should be the columns headers)
def write_sql(tablename, in_array):
    headers = in_array[0]
    in_array = in_array[1:]
    val = ""
    for x in range(len(headers)):
        val += "?, "
    val = val[:-2]
    columns = str(headers).replace("'", "").replace("[", "").replace("]", "")
    db_conn = pyodbc.connect('DSN={};dbname={};UID={};PWD={}'.format(SQL_DSN, SQL_DBNAME, SQL_USER, SQL_PASSW))
    query_str = "INSERT INTO "+tablename+"("+columns+") VALUES ("+val+")"
    cursor = db_conn.cursor()
    cursor.executemany(query_str, in_array)
    count = cursor.rowcount
    db_conn.commit()

    return count

################################################## Main Program #####################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_file', type=str, required=True, help='Path to the yaml config file')
    parser.add_argument('-v', '--vis', type=str, required=True, help='Visualization ID')
    parser.add_argument('-t', '--table', type=str, required=True, help='SQL Table to store the extracted data')
    parser.add_argument('-d', '--days', required=True, help="Number of days to query for")
    parser.add_argument('--debug', action='store_true', required=False, help='Enable debug mode logging.')
    args = parser.parse_args()

    DEBUG = args.debug
    set_logger("wazuh2sql", log_file)
    logging.info("# Starting the conversion")
    try:
        cfg_text = open(args.config_file, "r")
        cfg_dict = yaml.safe_load(cfg_text)

        IDX_IP = cfg_dict['connection']['wazuh']['indexerIp']
        DASH_IP = cfg_dict['connection']['wazuh']['dashboardIp']
        IDX_USER = cfg_dict['connection']['wazuh']['username']
        IDX_PASSW = cfg_dict['connection']['wazuh']['password']

        SQL_DSN = cfg_dict['connection']['sql']['DSN']
        SQL_DBNAME = cfg_dict['connection']['sql']['database']
        SQL_USER = cfg_dict['connection']['sql']['username']
        SQL_PASSW = cfg_dict['connection']['sql']['password']

        COLUMNS = cfg_dict['columns']

        logging.debug("All configurations readed from the config file: {}".format(args.config_file))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error obtaining settings from config file: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    
    try:
        logging.info("Querying the Wazuh Indexer")
        visualization, idx_pattern = get_vis(args.vis)
        search_query = build_aggs(visualization, args.days)
        results = search(search_query, idx_pattern)
        logging.debug("Parsing the results")
        res_key = list(results.keys())[0]
        arr_results = extract_data(results, key=int(res_key))
        timestamp = str(datetime.now())
        logging.info("Inserting data into SQL Table: {}".format(args.table))
        for row in arr_results:
            row.append(timestamp)
        head = match_columns(visualization)
        logging.debug("Trying to insert data into columns: {}".format(head))
        arr_results = [head] + arr_results
        affected_rows = write_sql(args.table, arr_results)
        logging.info("{} Rows insterted into the SQL Table".format(affected_rows))
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error converting the data: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
