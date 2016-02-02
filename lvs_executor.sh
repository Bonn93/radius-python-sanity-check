#!/bin/bash

dirname=$(dirname $0)
username=""
password=""
secret=""
${dirname}/check_radius.py --username ${username} --password ${password} --host ${1} --secret ${secret} > /dev/null 2>&1
if [ $? -eq 0 ]; then
   echo "OK"
else
   echo "FAIL"
fi
