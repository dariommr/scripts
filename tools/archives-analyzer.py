import os, sys
import json
import numpy as np
from datetime import datetime
import codecs
import logging
import argparse

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

def getstats(arch_dict, top):
    values, counts = np.unique(arch_dict, return_counts=True)
    if top <= len(counts):
        ind = np.argpartition(counts, -top)[-top:]
    else:
        ind = range(len(values))
    arr_stats = []
    for i in ind:
        tmp_item = {"name": values[i], "count": int(counts[i])}
        perc = counts[i]*100/total 
        tmp_item["perc"] = "{:.2f}".format(perc)
        arr_stats.append(tmp_item)
    return arr_stats

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--top', type=int, required=True, help='Top values to get from statistics')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    parser.set_defaults(debug=False)
    args = parser.parse_args()

    top_count = args.top
    DEBUG = args.debug
    set_logger("archive-analyzer")
    try:
        arch_text = codecs.open("/var/ossec/logs/archives/archives.json", "r",encoding='utf-8', errors='ignore')
        logging.info("Archives file read successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error reading the archives file: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    logging.info("Analyzing the archives content")
    try:
        first_alert = {}
        alert = []
        location = []
        decoders = []
        agents = []
        workers = []
        count = 0
        for line in arch_text:
            count += 1
            alert = json.loads(line)
            if first_alert == {}:
                first_alert = alert
            location.append(alert["location"])
            if "name" in alert["decoder"]:
                decoders.append(alert["decoder"]["name"])
            agents.append(alert["agent"]["name"])
            workers.append(alert["manager"]["name"])
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error analyzing the archives content: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)
    arch_text.close()

    try:
        last_timestamp = alert["timestamp"][:-5]
        first_timestamp = first_alert["timestamp"][:-5]
        first_datetime = datetime.strptime(first_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
        last_datetime = datetime.strptime(last_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
        total_time = last_datetime - first_datetime
        total = count
        global_stats = {"_global": { "first-event": first_timestamp, "last-event": last_timestamp, "total-time": str(total_time), "total-events": total}}
        logging.info("Global statistics calculated successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error calculating global statistics: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    try:
        global_stats["location-stats"] = getstats(location, top_count)
        global_stats["decoder-stats"] = getstats(decoders, top_count)
        global_stats["agents-stats"] = getstats(agents, top_count)
        global_stats["worker-stats"] = getstats(workers, top_count)
        logging.info("Single statistics obtained successfully")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error while calculating single statistics: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)

    try:
        out_file = open("archives_stats.json", "w")
        out_file.write(json.dumps(global_stats, indent=4, sort_keys=True))
        out_file.close()
        logging.info("Statistics file successfully created")
    except Exception as e:
        exc = sys.exc_info()
        logging.error("Error writing the statistics file: [{}] {}".format(exc[2].tb_lineno, e))
        sys.exit(1)