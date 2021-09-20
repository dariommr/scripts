# DEFINE THE ELASTICSEARCH PARAMETERS
ELASTIC_IP="localhost"
ELASTIC_USR="admin"
ELASTIC_PWD="admin"
FROM="2021.07.30"

# MAIN PROGRAM
echo -e "GETTING THE INDICES LIST\n"
ALL_INDICES=$(curl -sS -k -u $ELASTIC_USR:$ELASTIC_PWD -XGET "https://$ELASTIC_IP:9200/_cat/indices/wazuh-alerts-*?s=index&h=index")
LATEST=$(curl -sS -k -u $ELASTIC_USR:$ELASTIC_PWD -XGET "https://$ELASTIC_IP:9200/_cat/indices/wazuh-alerts-*?s=index&h=index" | head -n 1)

# CHECKING FOR PREVIOUS EXECUTIONS OF THE SCRIPT
echo -e "CHECKING IF THE SCRIPT WAS RUNNING BEFORE\n"
if test -d "indices"; then
    echo -e "<indices> DIRECTORY EXISTS\n"
    LATEST=$(ls -r indices/wazuh-alerts-* | head -1)
    LATEST=${LATEST//indices\//}
    LATEST=${LATEST//.json/}
else
    echo -e "CREATING <indices> DIRECTORY TO DUMP THE DATA IN\n"
    mkdir indices
fi

FROM_DATE=$(date -d ${FROM//./} +%s)
LATEST=${LATEST//wazuh-alerts-4.x-/}
LAT_DATE=$(date -d ${LATEST//./} +%s)
if [[ $FROM_DATE -ge $LAT_DATE ]]; then
    echo -e "\tSTARTING FROM DATE $FROM"
    LATEST_DATE=$FROM_DATE
else
    echo -e "\tSTARTING FROM DATE $LATEST"
    LATEST_DATE=$LAT_DATE
fi

# DUMPING ALL THE INDICES INTO JSON FILES
echo -e "DUMPING THE DATA TO FILES\n"
while IFS= read -r line; do
    STR_DATE=${line//wazuh-alerts-4.x-/}
    LN_DATE=$(date -d ${STR_DATE//./} +%s)
    if [[ $LN_DATE -ge $LATEST_DATE ]]; then
        echo -e "\tPROCESSING INDEX $line"
        curl -sS -k -u admin:$ELASTIC_USR -XGET "https://$ELASTIC_IP:9200/$line/_search" -H 'Content-Type: application/json' -d'{"query":{"match_all":{}}}' | jq -c '.hits.hits[]' >indices/$line.json
    fi
done <<< "$ALL_INDICES"
echo -e "\nFINISHED PROCESSING INDICES\n"
echo -e "CHECK THE <indices> DIRECTORY\n"
