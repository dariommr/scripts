#!/bin/bash

# Stop wazuh-manager

systemctl stop wazuh-manager

# Create a tmp folder to locate agent-groups file
if [ -d "/var/ossec/tmp/agent-groups" ]
then
    rm -rf /var/ossec/tmp/agent-groups
fi

mkdir /var/ossec/tmp/agent-groups 2>/dev/null

# Create a tmp folder to locate agent db file
if [ -d "/var/ossec/tmp/agent-db" ]
then
    rm -rf /var/ossec/tmp/agent-db
fi

mkdir /var/ossec/tmp/agent-db 2>/dev/null

# Create agent-groups and agent-db files for every valid agent in tmp/
echo "Creating agent-groups and agent-db files for valid agents"
for id in $(grep -o '^[[:digit:]]\{3,\}[[:space:]][^!#]' /var/ossec/etc/client.keys | egrep -oh ^[[:digit:]]\{3,\})
do
    touch /var/ossec/tmp/agent-groups/$id
    touch /var/ossec/tmp/agent-db/${id}.db
done

# Create wdb
touch /var/ossec/tmp/agent-db/wdb

echo "Moving residual files to /tmp"

# Move residual agent-groups files to tmp folder
# Valid agent-groups files stay
for FILE in $(ls /var/ossec/queue/agent-groups)
do
    mv -n /var/ossec/queue/agent-groups/${FILE} /var/ossec/tmp/agent-groups/
done

# Move residual agents dbs
# Valid agent db files stay
for FILE in $(ls /var/ossec/queue/db)
do
    mv -n /var/ossec/queue/db/${FILE} /var/ossec/tmp/agent-db/
done

# Delete tmp content
echo "Deleting residual files from /tmp"
rm -rf /var/ossec/tmp/agent-groups
rm -rf /var/ossec/tmp/agent-db

systemctl start wazuh-manager