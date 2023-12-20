#!/bin/bash

python3 test_cmd_gen.py $1 $2 > foo.sh
bash foo.sh | grep -A 2 'Received signature' > report.txt
