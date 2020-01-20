#!/bin/bash
# set -x

# $1 = experiment 
# E.g 170719

inputdir=/home/lupones/manager/experiments/individual/2w/resultTables/
outputdir=/home/lupones/manager/experiments/individual/2w/scatter-2w/
sudo python3 ./scatter-appType-graph.py -fn noncritical.yaml -fn sensitive.yaml -fn medium.yaml -fn bully.yaml -fn squanderer.yaml -id $inputdir -od $outputdir 

#inputdir=/home/lupones/manager/experiments/190510/test/resultTables/
#outputdir=/home/lupones/manager/experiments/190510/test/scatter/
#sudo python3 ./scatter-graph.py -fn /home/lupones/manager/experiments/190510/w.yaml -id $inputdir -od $outputdir 
