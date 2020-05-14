#!/bin/bash
# set -x


#workloads=/home/lupones/manager/experiments/$1/workloads$1.yaml
workloads=/home/lupones/manager/experiments/$1/$2.yaml
inputdir=/home/lupones/manager/experiments/$1
outputdir=/home/lupones/manager/experiments/$1

#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n stp -n antt -n interval -n unfairness -n geoipc -dp noPart_16ways -p noPart_16ways -p CPA_16ways
sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n stp -n antt -n interval -n unfairness -n geoipc -p noPart -p Dunn -p CA -p CPA -p CPA_v2 -p CPA_v3

#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n stp -n antt -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n geoipc -p noPart -p Dunn -p CA -p CPA  

#-p CAV2_Schwetman -p CAV2_Turkey
#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n ipc -p noPart -p criticalAware -p CAV2_ws2 -p CAV2_ws3  -p CAV2_ws4  -p CAV2_ws5 -p CAV2_ws6 -p CAV2_ws7 -p CAV2_ws8 -p CAV2_ws9 -p CAV2_ws10

#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n ipc -p noPart -p criticalAware -p criticalAwareV2 -p CAV2_monitor_llc_occup -p CAV2_conservative -p CAV2_filtering -p CAV2_conservative_filtering



