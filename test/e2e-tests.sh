#!/bin/bash -e

function sort_data {
    jq ".log.entries[] | .$1" $2 | sort
}

cd $(dirname "${BASH_SOURCE[0]}")
for f in captures/*.pcap
do
    FILE=captures/$(basename -s.pcap "$f")
    ../pcap2har $f > $FILE.output
    diff <(sort_data request.url "$FILE.output") <(sort_data request.url "$FILE.expected")
    diff <(sort_data response.content.text "$FILE.output") <(sort_data response.content.text "$FILE.expected")
done
