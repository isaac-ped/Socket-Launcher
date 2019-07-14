#!/bin/bash

LABEL=$1
PORT=$2
if [[ $PORT == "" ]]; then
    echo "Usage $0 LABEL PORT"
    exit -1;
fi

mkdir -p proxy_tests/iperf_$LABEL/


for simul in `seq 1 100`; do
    iperf3 -c 192.168.0.9 -p $PORT -i .1 -P $simul -J -t 4 > proxy_tests/iperf_$LABEL/simul_${simul}.txt
done
