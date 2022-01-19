import argparse
import socket
import json
import yaml
import os, sys
import logging
import urllib.request as urlrequest
from deepdiff import DeepDiff

template_filename = "wazuh-template.json"
custom_fields_filename = "custom-fields.yml"
url_template = "https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json"

def set_logger(name, logfile=None):
    hostname = socket.gethostname()

    format = '%(asctime)s {0} {1}: %(message)s'.format(hostname, name)

    logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)

    #print logging.Logger.manager.loggerDict

    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

#FUNCTION to obtain the differences between base dictionary and another modified from the first.
def parse_diff(base_dict, modified_dict, type):
    diff = DeepDiff(base_dict,modified_dict)
    arr_results = []
    try:
        for item in diff[type]:
            str_item = str(item)
            str_item = str_item[:len(str_item)-2].replace("root['", "")
            arr_item = str_item.split("']['")
            temp = {}
            buff = modified_dict
            for key in reversed(arr_item):
                if not temp:
                    for key in arr_item:
                        buff = buff[key]
                    temp[key] = buff
                else:
                    temp = {key: temp}
            arr_results.append(temp["mappings"]["properties"]["data"]["properties"])
    except Exception as e:
        logging.debug("Couldn't get the differences: {0}".format(str(e)))
    return arr_results

#FUNCTION to create a yaml output with the differences (addings and changes) between two dictionaries.
def create_yaml(template1, template2):
    logging.info("Looking for custom fields in the local Template")
    addings_dict = parse_diff(template1,template2,'dictionary_item_added')
    logging.info("Looking for changed values in the local Template")
    changes_dict = parse_diff(template1,template2,'values_changed')
    final_dict = {}
    final_dict["addings"] = addings_dict
    final_dict["changes"] = changes_dict
    return yaml.dump(final_dict)

if __name__ == "__main__":
    start_dir = os.path.dirname(os.path.realpath(__file__))
    def checker(f):
        if not os.path.isfile(os.path.join(start_dir, f)):
            logging.error("Error: The file does not exists")
            raise argparse.ArgumentTypeError("You must specify an existent file in the current path")
        return f
    parser = argparse.ArgumentParser(prog="fields-manager.py", description='Manage Custom Fields for Wazuh Template')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-d', '--getdiff', action='store_true', help='Obtain differences between Default Template and local template.')
    group.add_argument('-u', '--update', action='store_true', help='Updates local template with new/modified fields.')
    parser.add_argument('-f', '--inputfile', metavar='filename', default="custom-fields.yml", type=checker, required = False, help='Specify the custom fields file')
    args = parser.parse_args()

    set_logger('fields-manager', logfile="fields-manager.log")

    #Read files and URL
    logging.info("fields-manager.py received the arguments, processing")
    logging.info("Downloading and processing the Wazuh Template from the repository")
    try:
        current_template = urlrequest.urlopen(url_template)
        current_json = json.load(current_template)
        logging.debug("Wazuh Template downloaded and processed successfully")
    except Exception as e:
        logging.debug("Unable to process the template: {0}".format(url_template))
        logging.error("Error processing the template: {0}".format(str(e)))
        sys.exit(1)

    logging.info("Opening the local Wazuh Template file")
    try:
        local_template = open(os.path.join(start_dir, template_filename), "r")
        local_json = json.load(local_template)
        local_template.close
        logging.debug("Wazuh Template file processed successfully")
    except Exception as e:
        logging.debug("Unable to open the template file: {0}".format(template_filename))
        logging.error("Error processing the template: {0}".format(str(e)))
        sys.exit(1)

    if args.getdiff:
        #Create a YAML file with the differences between the templates
        logging.info("Extracting differences")
        try:
            config_file = open(os.path.join(start_dir, "fields.yml"), "w")
            config_file.write(create_yaml(current_json, local_json))
            logging.debug("fields.yml file created successfully with the differences between the stock template and the local template")
        except Exception as e:
            logging.debug("Error trying to write the file: fields.yml")
            logging.error("Error: {0}".format(str(e)))
            sys.exit(1)
        logging.info("Finished Extracting differences. Check the output file: fields.yml")

    if args.update:
        logging.info("Processing the Custom fields file")
        try:
            newfields_file = open(os.path.join(start_dir, args.inputfile), "r")
            newfields_dict = yaml.load(newfields_file, Loader=yaml.FullLoader)
            newfields_file.close
            logging.debug("Custom fields file read successfully")
        except Exception as e:
            logging.debug("Error reading the content of the file: {0}".format(args.inputfile))
            logging.error("Error: {0}".format(str(e)))
            sys.exit(1)
        #Insert the addings into the template
        logging.info("Inserting the custom fields (addings and changes) into the wazuh-template")
        try:
            new_dict = local_json
            if not newfields_dict["addings"] is None:
                for item in newfields_dict["addings"]:
                    new_dict["mappings"]["properties"]["data"]["properties"].update(item)
            if not newfields_dict["changes"] is None:
                for item in newfields_dict["changes"]:
                    new_dict["mappings"]["properties"]["data"]["properties"].update(item)
            local_template = open(os.path.join(start_dir, template_filename), "w")
            local_template.write(json.dumps(new_dict, indent=4))
            local_template.close()
            logging.debug("Custom fields changed successfully")
        except Exception as e:
            logging.debug("Error trying to insert the custom fields in the template")
            logging.error("Error: {0}".format(str(e)))
            sys.exit(1)
        logging.info("wazuh-template file updated successfully")
