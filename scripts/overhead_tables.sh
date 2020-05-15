#!/bin/bash

# $1 = experiment folder name (e.g. 170919)
# $2 = policy (e.g. CPA)

inputdir=~/manager/tests/$1/$2/log
outputdir=~/manager/tests/$1/overhead/

mkdir $outputdir

# Create csv file
fn=$(echo $outputdir$2"-times.csv")
touch $fn

# Add header line 
echo "interval,overhead"
echo "interval,overhead" >> $fn 

for filename in $inputdir/*.log; do
  
	# Get total overhead from log file
	aux=$(cat $filename | grep "TOTAL OVERHEAD" | cut -c 51-)
	overhead=${aux::-3}

	# Get last inteval executed from log file
	aux=$(cat $filename | grep "Interval" | cut -c 60- | tail -1)
	interval=${aux::-10}
	interval="$(echo -e "${interval}" | sed -e 's/[[:space:]]*$//')"

	# Add new entry to table
	echo $interval","$overhead
	echo $interval","$overhead >> $fn

done 


