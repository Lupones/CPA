#!/bin/bash
# set -x

inputdir=~/manager/tests/$1
outputdir=~/manager/tests/$1/overhead/

sudo python3 ./overhead_calculation.py -id $inputdir -od $outputdir -p noPart -p CA -p CPA

