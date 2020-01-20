import argparse
import numpy as np
import os
import pandas as pd
import re
import scipy.stats
import sys
import yaml
import glob
import itertools
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

#def pltcolor(lst):
#    cols=[]
#    for l in lst:
#        if l < 0.45:
#            cols.append('dimgrey')
#        elif l < 0.7:
#            cols.append('orange')
#       elif l < 1:
#            cols.append('lightcoral')
#        elif l < 1.3:
#            cols.append('blue')
#        elif l < 1.6:
#            cols.append('red')
#        elif l < 1.9:
#            cols.append('brown')
#        else:
#            cols.append('green')
#    return cols

def pltcolor(lst):
    cols=[]
    for l in lst:
        if l < 0.6:
            cols.append('dimgrey')
        elif l < 1.3:
            cols.append('orange')
        else:
            cols.append('green')
    return cols


def main():
    parser = argparse.ArgumentParser(description='Process results of workloads by intervals.')
    parser.add_argument('-od', '--outputdir', default='./output', help='Directory where output files will be placed')
    parser.add_argument('-id', '--inputdir', default='./data', help='Directory where input are found')
    parser.add_argument('-fn', '--fileName', action='append', default=[], help='Files containing lists of apps or workloads names.')
    args = parser.parse_args()

    outputPath = os.path.abspath(args.outputdir)
    os.makedirs(os.path.abspath(outputPath), exist_ok=True)

    colors = itertools.cycle(["r", "b", "g", "m", "c"])

    MPKIL3_15std = 0
    MPKIL3_3std = 0
    dfmpkil3 = pd.DataFrame()
    names = ['critical.yaml','noncritical.yaml']
    for fileName in names:
        fileNamePath = "/home/lupones/manager/scripts/workloads_apps/" + fileName
        with open(fileNamePath, 'r') as f:
            workloads = yaml.load(f)
        for wl_id, wl in enumerate(workloads):
            wl_show_name = "-".join(wl)
            apps = wl_show_name.split("-")
            appN = 0
            for app in apps:
                wl_in_path = args.inputdir + "/" + wl_show_name + "/0" + str(appN) + "_" + app + "-intervalDataTable.csv"
                dfWay = pd.read_table(wl_in_path, sep=",")
                dfmpkil3 = dfmpkil3.append(dfWay, ignore_index=True)

    MPKIL3_3std = dfmpkil3['MPKIL3:mean'].mean() + 3*dfmpkil3['MPKIL3:mean'].std()
    MPKIL3_15std = dfmpkil3['MPKIL3:mean'].mean() + 1.5*dfmpkil3['MPKIL3:mean'].std()
    print("MPKIL3_3std: " + str(MPKIL3_3std))
    print("MPKIL3_15std: " + str(MPKIL3_15std))

    for fileName in args.fileName:
        #fig, ax = plt.subplots()
        print(fileName)
        fileNamePath = "/home/lupones/manager/scripts/workloads_apps/" + fileName
        with open(fileNamePath, 'r') as f:
            workloads = yaml.load(f)

        dfN = pd.DataFrame(columns=['interval','app','HPKIL3:mean','MPKIL3:mean','IPC:mean'])

        for wl_id, wl in enumerate(workloads):
            wl_show_name = "-".join(wl)
            apps = wl_show_name.split("-")

            appN = 0
            for app in apps:
                print(app)
                # Dataframe for interval table
                wl_in_path = args.inputdir + "/" + wl_show_name + "/0" + str(appN) + "_" + app + "-intervalDataTable.csv"
                dfWay = pd.read_table(wl_in_path, sep=",")
                dfWay = dfWay[['interval','app','HPKIL3:mean','MPKIL3:mean','IPC:mean','l3_Mbytes_occ:mean']]

                if dfN.empty:
                    dfN = dfWay
                else:
                    dfN = dfN.append(dfWay, ignore_index=True)

                appN = appN + 1

        dfN = dfN.set_index(['interval','app'])
        groups = dfN.groupby(level=[1])

        metrics = ["HPKIL3:mean","l3_Mbytes_occ:mean"]
        for metric in metrics:
            fig, ax = plt.subplots()
            Y = dfN["MPKIL3:mean"].tolist()
            YI = dfN["IPC:mean"].tolist()
            X = dfN[metric].tolist()
            cols=pltcolor(YI)
            ax.scatter(X,Y,marker="x", color=cols, label=app)

            outputPathApp = outputPath + "/"+metric+"-MPKI-" + fileName + "-scatter-xs.pdf"
            print(outputPathApp)
            plt.ylabel('MPKI_LLC')
            plt.xlabel(metric)
            title = fileName.split(".")
            title = title[0]
            plt.title(title.capitalize() + " apps. graph with 2 cache ways")
            plt.ylim(0,15)
            if metric == "HPKIL3:mean":
                plt.xlim(0,45)
                plt.axvline(x=10, color='k', linestyle='--')
                plt.axvline(x=0.5, color='k', linestyle='--')
                plt.axhline(y=0.5, color='k', linestyle='--')
                plt.axhline(y=10, color='k', linestyle='--')
                plt.xlabel("HPKI_LLC")
            elif metric == "l3_Mbytes_occ:mean":
                plt.xlim(0,20)
                plt.xlabel("LLC Occupancy (MB)")
            #if fileName == "bully.yaml":
                #plt.axvline(x=10, color='k', linestyle='--')
                #plt.axhline(y=10, color='k', linestyle='--')
            #elif fileName == "squanderer.yaml" or fileName == "critical.yaml" or fileName == "medium.yaml" or fileName == "sensitive.yaml":
                #plt.axvline(x=0.5, color='k', linestyle='--')
                #plt.axhline(y=MPKIL3_15std, color='k', linestyle='--')

            ax.grid(True)
            # add custom legend
            green = mpatches.Patch(color='green', label='IPC > 1.3')
            orange = mpatches.Patch(color='orange', label='IPC 0.6 - 1.3')
            dimgrey = mpatches.Patch(color='dimgrey', label='IPC < 0.6')
            plt.legend(handles=[green, orange, dimgrey])

            #green = mpatches.Patch(color='green', label='IPC > 1.9')
            #brown = mpatches.Patch(color='brown', label='IPC 1.6 - 1.9')
            #red = mpatches.Patch(color='red', label='IPC 1.3 - 1.6')
            #blue = mpatches.Patch(color='blue', label='IPC 1.0 - 1.3')
            #lightcoral = mpatches.Patch(color='lightcoral', label='IPC 0.7 - 1.0')
            #orange = mpatches.Patch(color='orange', label='IPC 0.7 - 0.45')
            #dimgrey = mpatches.Patch(color='dimgrey', label='IPC < 0.45')
            #plt.legend(handles=[green, brown, red, blue, lightcoral, orange, dimgrey])

            # plot and save graph
            plt.show()
            plt.savefig(outputPathApp)
            plt.clf()
            plt.cla()
            plt.close()


# El main es crida des d'ací
if __name__ == "__main__":
    main()
