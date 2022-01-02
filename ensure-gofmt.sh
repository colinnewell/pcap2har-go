#!/bin/sh
list=$(gofmt -l -s .)
if [ -n "$list" ]
then
    echo "Files need to be gofmt'd."
    for f in $list
    do
        # this format means if an editor
        # is reading the output it can take you to the file.
        echo $f:1:0: Need to run gofmt -w -s $f
    done
    exit 1
fi
