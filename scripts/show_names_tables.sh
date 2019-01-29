#!/bin/bash
# set -x


#workloads=/home/lupones/manager/experiments/$1/workloads$1.yaml
workloads=/home/lupones/manager/experiments/$1/$2.yaml
inputdir=/home/lupones/manager/experiments/$1
outputdir=/home/lupones/manager/experiments/$1

sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n stp -n antt -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n ipc -p noPart -p criticalAware -p CAV2_Schwetman -p CAV2_Carling -p CAV2_q3 -p CAV2_mad -p CAV2_Turkey -p CAV2_3std -p CAV2_auto75 -p CAV2_2.5std -p CAV2_2std -p cad 


#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n stp -n antt -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n ipc -p noPart -p criticalAware  -p CAV2_Schwetman_0 -p CAV2_Schwetman_1 -p CAV2_Schwetman_2 -p CAV2_Schwetman_3 -p CAV2_Schwetman_4 -p CAV2_Schwetman_5 -p cad

#-p CAV2_Schwetman -p CAV2_Turkey
#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n ipc -p noPart -p criticalAware -p CAV2_ws2 -p CAV2_ws3  -p CAV2_ws4  -p CAV2_ws5 -p CAV2_ws6 -p CAV2_ws7 -p CAV2_ws8 -p CAV2_ws9 -p CAV2_ws10

#sudo python3 ./show_names_tables.py -w $workloads -id $inputdir -od $outputdir -n power/energy-pkg/ -n power/energy-ram/ -n interval -n unfairness -n ipc -p noPart -p criticalAware -p criticalAwareV2 -p CAV2_monitor_llc_occup -p CAV2_conservative -p CAV2_filtering -p CAV2_conservative_filtering



