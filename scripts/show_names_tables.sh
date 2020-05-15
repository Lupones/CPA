#!/bin/bash

workloads=~/manager/tests/$1/$2.yaml
inputdir=~/manager/tests/$1
outputdir=~/manager/tests/$1

sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n stp -n antt -n interval -n unfairness -n geoipc -p noPart -p CA -p CPA 



