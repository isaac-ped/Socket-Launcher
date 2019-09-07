#!/bin/bash

LABEL=$1
PORT=$2
if [[ $PORT == "" ]]; then
    echo "Usage $0 LABEL PORT"
    exit -1;
fi

mkdir -p proxy_tests/$LABEL/


for simul in `seq 1 200`; do
    taskset 0xF ./echo_client 192.168.0.9 $PORT $simul 1000 proxy_tests/$LABEL/simul_${simul}.txt
done
