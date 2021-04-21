#GETTING ARGUMENTS
usage() {
  echo "USAGE: reindex.sh (-a|--all yes | -f|--file /path/file) -s|--server https://address:port -u|--user user -p|--pass password"
  echo "  -f or --file    Specify the path of the file that contains the list of Indices to reindex. No puede ser utilizado con -a"
  echo "  -a or --all     Specify if you need to reindex all the indices. No puede ser utilizado con -f"
  echo "  -s or --server  Specify the URL of the Elasticsearch server with protocol and port"
  echo "  -u or --user    Specify the administrator user of Elasticsearch"
  echo "  -p or --pass    Specify the password of the administratior user of Elasticsearch"
  echo "  -h or --help    Display this help"
}

if [[ $# -eq 0 ]] ; then
  usage
  exit
fi

POSITIONAL=()
while [[ $# -gt 0 ]]
do
  key="$1"
  case $key in
    -f|--file)
    FILE="$2"
    shift # past argument
    shift # past value
    ;;
    -a|--all)
    ALL="$2"
    shift # past argument
    shift # past value
    ;;
    -s|--server)
    SERVER="$2"
    shift # past argument
    shift # past value
    ;;
    -u|--user)
    USER="$2"
    shift # past argument
    shift # past value
    ;;
    -p|--pass)
    PASS="$2"
    shift # past argument
    shift # past value
    ;;
    -h|--help)
    HELP="yes"
    shift # past argument
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
  esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if  [[ $HELP == "yes" ]] || [[ -z $USER ]] || [[ -z $PASS ]] || [[ -z $SERVER ]]; then
  usage
  exit
fi

if [[ ! -z $ALL ]] && [[ ! -z $FILE ]] ; then
  usage
  exit
fi

if [ $ALL == "yes" ] ; then
  echo -e "\nThe -a|--all feature is not available yet\n"
  usage
  exit
fi

#REINDEX FUNCTION
reindex() {
  ENDPR="/_reindex?wait_for_completion=false"
  HEAD='Content-Type: application/json'
  PART_QRY='{"source": {"index": "%s"},"dest": {"index": "%s"}}'
  FULL_QRY=$(printf "$PART_QRY" "$INDEX" "$INDEX_BKP")
  curl -s -u $USER:$PASS -k -X POST $SERVER$ENDPR -H "$HEAD" -d "$FULL_QRY" >>/tmp/tasks.json
  TMP=$(tail -n 1 /tmp/tasks.json)
  echo -e -n "\n" >>/tmp/tasks.json
  RES=$(echo $TMP | sed -e 's/{//g' | sed -e 's/}//g' | sed -e 's/"//g' | sed -e 's/task://g')
}

#GET TASK STATUS FUNCTION
task_state() {
  TSK=$(echo "$LINE" | awk -F ',' '{print $2}')
  ENDPT="/_tasks/$TSK"
  if [[ $(curl -s -u $USER:$PASS -k -X GET $SERVER$ENDPT) == *'"completed":true'* ]]; then STATUS="Completed"; else STATUS="Not Completed"; fi
}

#====== MAIN PROGRAM ========
echo "PHASE [1] IN PROGRESS"
echo "Reindex to temporary indices"
while IFS= read -r INDEX; do
  INDEX_BKP=$INDEX"-bkp"
  reindex
  echo $INDEX","$RES >>/tmp/tasks.lst
  echo "Reindexing $INDEX to $INDEX_BKP"
done < $FILE
#GET TASKS STATUS, WHEN COMPLETED, REINDEX AGAIN
TIMEOUT=3600                          #TIMEOUT UNTIL THE STATUS CHECK THROWS AN ERROR
echo -e "\nPHASE [2] IN PROGRESS"
echo "Reindex to final indices"
while IFS= read -r LINE; do
  readarray -d , -t strarr <<<"$LINE"
  IX="${strarr[0]}"
  TSK="${strarr[1]}"
  STATUS="Not Completed"
  #WAIT TASK FOR COMPLETION
  SECONDS=0
  while [ "$STATUS" == "Not Completed" ] && [ $SECONDS -lt $TIMEOUT ]
  do
    task_state
    sleep 5
  done
  echo -e "\nReindex to $IX-bkp is $STATUS"
  if [[ $STATUS == "Not Completed" ]]; then
    echo "[ERROR] The reindex of $$IX-bkp was Not Completed (timeout reached) and you need to check the Status of the task $TSK and continue manually"
    continue
  fi
  #DELETE THE ORIGINAL INDEX
  echo "Deleting the Index $IX"
  if [[ $(curl -s -u $USER:$PASS -k -X DELETE $SERVER"/"$IX) == *'"acknowledged":true'* ]]; then DEL="Completed"; else DEL="Failed"; fi
  sleep 10
  echo "Delete $DEL"
  INDEX=$IX"-bkp"
  INDEX_BKP=$IX
  reindex
  echo $INDEX","$RES >>/tmp/tasksp2.lst
  echo "Reindex to $IX is In Progress"
done < /tmp/tasks.lst

echo -e "\nPHASE [3] IN PROGRESS"
echo "Cleaning temporary data"
while IFS= read -r LINE; do
  readarray -d , -t strarr <<<"$LINE"
  IX="${strarr[0]}"
  TSK="${strarr[1]}"
  STATUS="Not Completed"
  #WAIT TASK FOR COMPLETION
  SECONDS=0
  while [ "$STATUS" == "Not Completed" ] && [ $SECONDS -lt $TIMEOUT ]
  do
    task_state
    sleep 5
  done
  echo "Reindex to $IX-bkp is $STATUS"
  if [[ $STATUS == "Not Completed" ]]; then
    echo "[ERROR] The reindex of $$IX-bkp was Not Completed (timeout reached) and you need to check the Status of the task $TSK and continue manually"
    continue
  fi
  #DELETE THE ORIGINAL INDEX
  echo "Deleting the Index  $IX"
  if [[ $(curl -s -u $USER:$PASS -k -X DELETE $SERVER"/"$IX) == *'"acknowledged":true'* ]]; then DEL="Completed"; else DEL="Failed"; fi
  sleep 10
  echo "Delete $DEL"
done < /tmp/tasksp2.lst

echo -e "\nRemoving temporary files"
#REMOVE TEMP FILES
rm -rf /tmp/tasks.json
rm -rf /tmp/tasks.lst
rm -rf /tmp/tasksp2.lst
echo -e "\nFINISHED\n"