import argparse
import logging
import requests
import json
import urllib3
import pandas as pd
import matplotlib.pyplot as plt
import os, sys
import xml.etree.ElementTree as ET
import smtplib
from email.message import EmailMessage
from email.utils import make_msgid
import mimetypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
start_dir = os.path.dirname(os.path.realpath(__file__))
#start_dir = "/var/ossec/etc/lists/"
cdb_list = os.path.join(start_dir, "report-list")

# Configuring logger
def set_logger(name, logfile=None):
    hostname = os.uname()[1]

    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)

    logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    #print logging.Logger.manager.loggerDict

    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

# Function to send emails
def send_email(FROM, TO, SERVER, MESSAGE):
    em = EmailMessage()
    asparagus_cid = make_msgid(domain="wazuh.com")
    msg_body = MESSAGE
    em.add_alternative(msg_body.format(asparagus_cid=asparagus_cid[1:-1]), subtype='html')
    em['To'] = TO
    em['From'] = FROM
    em['Subject'] = "Wazuh Report"
    try:
        mailserver = smtplib.SMTP(SERVER, 25)
        mailserver.ehlo()
        mailserver.send_message(em)
        mailserver.close()
        logging.info('Successfully sent the mail to {}'.format(TO))
    except Exception as e:
        logging.error("Failed to send mail with error: {}".format(e))
        sys.exit(1)

# Function to Get the Visualization parameters
def get_vis(vis_id):
    hook_url = "https://"+kibana_ip+"/api/saved_objects/visualization/"+vis_id
    try:
        result = requests.get(hook_url, auth=(user, passw), verify=False)
        data = json.loads(result.text)
        logging.info("Retrieved visualization information from Kibana successfully")
    except Exception as e:
        logging.error("Failed to retrieve visualization information: {}".format(e))
        sys.exit(1)
    query_config = json.loads(data["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    vis_configs = json.loads(data["attributes"]["visState"])
    if len(query_config["filter"]) > 0:
        vis_configs["filter"] = {}
        for item in query_config["filter"]:
            vis_configs["filter"].update(item["query"])
    return vis_configs

#Function to build the search query from the visualization parameters
def build_aggs(vis_aggs,days):
    aggs_dict = {}
    aggs_dict["aggs"] = {}
    metrics = []
    buckets = []
    for item in vis_aggs["aggs"]:
        if item["schema"] == "metric":
            metrics.append(item)
        else:
            buckets.append(item)
    id = "1"
    for bucket in buckets:
        inner_agg = {}
        inner_agg[bucket["id"]] = {}
        inner_agg[bucket["id"]]["terms"] = {}
        inner_agg[bucket["id"]]["terms"]["field"] = bucket["params"]["field"]
        inner_agg[bucket["id"]]["terms"]["order"] = {}
        for metric in metrics:
            if bucket["params"]["orderBy"] == metric["id"]:
                met = "_"+metric["type"]
                inner_agg[bucket["id"]]["terms"]["order"][met] = bucket["params"]["order"]
        inner_agg[bucket["id"]]["terms"]["size"] = bucket["params"]["size"]
        if "include" in bucket["params"]:
            inner_agg[bucket["id"]]["terms"]["include"] = bucket["params"]["include"]
        if "exclude" in bucket["params"]:
            inner_agg[bucket["id"]]["terms"]["exclude"] = bucket["params"]["exclude"]
        if buckets[0] == bucket:
            aggs_dict["aggs"].update(inner_agg)
            id = bucket["id"]
            aggs_dict["aggs"][id]["aggs"] = {}
        else:
            aggs_dict["aggs"][id]["aggs"].update(inner_agg)
    gte = "now-"+days+"d/d"
    srch_range = {"range":{"timestamp":{"gte":gte,"lte":"now/d","format":"strict_date_optional_time"}}}
    tmp_dict = {"query": {"bool": {"filter": []}}}
    tmp_dict["query"]["bool"]["filter"].append(srch_range)
    if "filter" in vis_aggs:
        tmp_dict["query"]["bool"]["filter"].append(vis_aggs["filter"])
    aggs_dict.update(tmp_dict)
    return aggs_dict

#Function to search in Elasticsearch
def search(data_dict):
    hook_url = "https://"+elastic_ip+":9200/_search"
    headers = {'Content-Type': 'application/json'}
    data = json.dumps(data_dict)
    try:
        json_result = requests.get(hook_url, auth=(user, passw), verify=False, headers=headers, data=data)
        result = json.loads(json_result.text)
        logging.info("Search executed in Elasticsearch server successfully")
    except Exception as e:
        logging.error("Failed to execute search in Elasticsearch server: {}".format(e))
        sys.exit(1)
    return result["aggregations"]

def extract_data(search_dict):
    dict_out = {}
    main_ids = []
    for k in search_dict:
        if k.isnumeric():
            main_ids.append(k)
    for id in main_ids:
        dict_out[id] = []
        dict_out["count"] = []
        sec_ids = []
        for sk in search_dict[id]["buckets"][0]:
            if sk.isnumeric():
                sec_ids.append(sk)
        for bucket in search_dict[id]["buckets"]:
            dict_out[id].append(bucket["key"])
            dict_out["count"].append(bucket["doc_count"])
            for sid in sec_ids:
                if not sid in dict_out:
                    dict_out[sid] = []
                for sbucket in bucket[sid]["buckets"]:
                    dict_out[sid].append(sbucket["key"])
    return dict_out

def create_table(vis_dict, search_dict):
    data_dict = extract_data(search_dict)
    json_table = {}
    for column in vis_dict["aggs"]:
        if column["schema"] == "metric":
            if "customLabel" in column["params"]:
                json_table[column["params"]["customLabel"]] = data_dict["count"]
            else:
                json_table[column["type"]] = data_dict["count"]
        else:
            if "customLabel" in column["params"]:
                json_table[column["params"]["customLabel"]] = data_dict[column["id"]]
            else:
                json_table[column["params"]["field"]] = data_dict[column["id"]]
    return json_table

def create_graph(in_json):
    plt.cla()
    plt.clf()
    if vis["type"] == "table":
        table = pd.DataFrame(in_json)
        title = "<h2>"+vis["title"]+" in the last "+timeframe+" days</h2>"
        html_table = table.to_html(index=False)
        html_graph = title+"\n"+html_table
        logging.info("Table graph created")
    if vis["type"] == "pie":
        table = pd.DataFrame(in_json)
        plt.pie(table[table.columns[0]],labels=table[table.columns[1]],autopct='%1.1f%%')
        plt.title(vis["title"]+" in the last "+timeframe+" days")
        plt.axis('equal')
        plt.savefig("pie.png")
        src_pie = os.path.join(start_dir, "pie.png")
        html_graph = '<img alt="{}" src="{}">'.format(vis["title"], src_pie)
        logging.info("Pie graph created")
    if vis["type"] == "histogram":
        if len(in_json.keys()) > 2:
            tmp_json = dict(list(in_json.items())[:2])
        else:
            tmp_json = in_json
        table = pd.DataFrame(tmp_json)
        plt.bar(table[table.columns[1]],table[table.columns[0]])
        plt.xlabel(table.columns[1])
        plt.ylabel(table.columns[0])
        plt.title(vis["title"]+" in the last "+timeframe+" days")
        plt.savefig("bar.png")
        src_bar = os.path.join(start_dir, "bar.png")
        html_graph = '<img alt="{}" src="{}">'.format(vis["title"], src_bar)
        logging.info("Bar graph created")
    plt.close()
    return html_graph

if __name__ == "__main__":
    set_logger("elastic-reports","elastic-reports.log")
    # Parsing the arguments
    parser = argparse.ArgumentParser(prog="custom-elastic-reports.py", description='Create email Reports from custom visualizations in Kibana')
    parser.add_argument('--creds', nargs='+', help='Elasticsearch credentials (user:password)', required=True)
    parser.add_argument('--elk-server', nargs='+', help='Elasticsearch server address', required=True)
    parser.add_argument('--kbn-server', nargs='+', help='Kibana server address')
    parser.add_argument('--smtp', nargs='+', help='SMTP Server address', required=True)
    parser.add_argument('--sender', nargs='+', help='Sender email address', required=True)
    parser.add_argument('--to', nargs='+', help='Recipient email address', required=True)
    args = parser.parse_args()
    if not (args.creds and args.elk_server and args.smtp and args.sender and args.to):
        parser.print_help(sys.stderr)
        sys.exit(1)
    user = args.creds[0].split(":")[0]
    passw = args.creds[0].split(":")[1]
    elastic_ip = args.elk_server[0]
    if args.kbn_server:
        kibana_ip = args.kbn_server[0]
    else:
        kibana_ip = elastic_ip
    smtp = args.smtp[0]
    sender = args.sender[0]
    rcpt = args.to
    logging.info("Parameters loaded successfully")

    try:
        file_list = open(cdb_list, "r")
        list = file_list.readlines()
        logging.info("Visualization list loaded successfully")
    except Exception as e:
        logging.error("Failed to load the CDB list: {}".format(e))
        sys.exit(1)

    logging.info("Writing the Report Body")
    body = "<body>\n<h1>Wazuh Report</h1>\n"
    for line in list:
        try:
            arr_line = line.split(":")
            vis_id = line.split(":")[0]
            if len(arr_line) > 1:
                timeframe = line.split(":")[1].strip()
            else:
                timeframe = "30"
            logging.info("Visualization parameters loaded for ID {} and timeframe {}".format(vis_id, timeframe))
        except Exception as e:
            logging.warning("Failed loading the visualization parameters, ignoring line")
            continue

        vis = get_vis(vis_id)
        aggs = build_aggs(vis,timeframe)
        srch_res = search(aggs)
        json_tbl = create_table(vis,srch_res)
        graph = create_graph(json_tbl)
        body = body+graph+"\n<hr>\n"
    body = body+"</body>"
    logging.info("Report creation process complete")
    
    send_email(sender,rcpt, smtp, body)
    logging.info("Reporting Tool has ended")
