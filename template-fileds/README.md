## Wazuh Fields Manager Tool: fields-manager.py
This tool is intended to be used as a tool for inserting (update mode) new fields in the `wazuh-template.json` file. Getting the fields from an input YAML file, and converting it to a python dictionary and then dumping it to the `wazuh-template.json`. Also it is capable of get the differences (getdiff mode) between the local (modified) template, and the template allocated in the Wazuh repositories.
```
usage: fields-manager.py [-h] (-d | -u) [-f filename]

Manage Custom Fields for Wazuh Template

optional arguments:
  -h, --help            show this help message and exit
  -d, --getdiff         Obtain differences between Default Template and local template.
  -u, --update          Updates local template with new/modified fields.
  -f filename, --inputfile filename
                        Specify the custom fields file
```
**Note:** This script uses the module `deepdiff`, so it is needed to install the module before using it: `pip install deepdiff`
