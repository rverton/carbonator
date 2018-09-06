#!/bin/bash
set -e

BURP_PATH=/home/robin/tools/BurpSuitePro/burpsuite_pro.jar
JAVAPATH=/usr/bin/java

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 scheme fqdn port path output.format"
	echo "Example: $0 http localhost 80 /path /tmp/result.xml"
	exit
fi

SCHEME=$1
FQDN=$2
PORT=$3
WPATH=$4
EXPORT=${5}

tempfile=$(mktemp -t -u carbonator.$FQDN.XXXXXX)

echo "Scanning '$SCHEME://$FQDN:$PORT$WPATH', exporting $EXPORT"

$JAVAPATH -jar -Xmx1024m $BURP_PATH $SCHEME $FQDN $PORT $WPATH $EXPORT --project-file=$tempfile --unpause-spider-and-scanner

# clean up project file
[ -e $tempfile ] && rm $tempfile

