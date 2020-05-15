#!/bin/bash

# $1 = experiment 
# E.g 170719

inputdir=~/manager/tests/TFM-TPDS/
outputdir=~/manager/tests/TFM-TPDS/graphs
workloadfile=~/manager/tests/TFM-TPDS/w.yaml

sudo python3 ./line-general-plots.py -fn w.yaml -id $inputdir -od $outputdir -fn $workloadfile -p CA -p CPA -m geoipc -m interval -m antt
