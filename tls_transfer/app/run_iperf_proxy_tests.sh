#!/bin/bash

LABEL=$1
PORT=$2
OUT=$3
if [[ $PORT == "" ]]; then
    echo "Usage $0 LABEL PORT"
    exit -1;
fi
if [[ $OUT == "" ]]; then
    OUT=proxy_tests/iperf_$LABEL/
fi

mkdir -p $OUT


for simul in `seq 1 100`; do
    iperf3 -c 192.168.0.10 -p $PORT -i .1 -P $simul -J -t 4 > $OUT/simul_${simul}.txt
    echo $simul
done
