#!/bin/bash
# set -x

# $1 = experiment 
# E.g 170719

inputdir=/home/lupones/manager/experiments/TFM-TPDS/
outputdir=/home/lupones/manager/experiments/TFM-TPDS/graphs
workloadfile=/home/lupones/manager/experiments/TFM-TPDS/w.yaml

sudo python3 ./line-general-plots.py -fn w.yaml -id $inputdir -od $outputdir -fn $workloadfile -p CPA -p CPA_no_LLC -m ipc -m interval -m antt
#sudo python3 ./line-general-plots.py -fn $2.yaml -id $inputdir -od $outputdir -fn $workloadfile -p Dunn -p CA -p CPA -m ipc -m interval -m antt
