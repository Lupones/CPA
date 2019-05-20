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

def pltcolor(lst):
    cols=[]
    for l in lst:
        if l < 0.7:
            cols.append('dimgrey')
        elif l < 1:
            cols.append('lightcoral')
        elif l < 1.3:
            cols.append('blue')
        elif l < 1.6:
            cols.append('red')
        elif l < 1.9:
            cols.append('brown')
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

    #fig, ax = plt.subplots()
    for fileName in args.fileName:

        fig, ax = plt.subplots()
        print(fileName)
        fileNamePath = "/home/lupones/manager/scripts/workloads_apps/" + fileName
        #fileNamePath = fileName
        with open(fileNamePath, 'r') as f:
            workloads = yaml.load(f)

        #cc = next(colors)

        dfN = pd.DataFrame(columns=['interval','app','HPKIL3:mean','MPKIL3:mean','IPC:mean'])

        for wl_id, wl in enumerate(workloads):

            #fig, ax = plt.subplots()

            wl_show_name = "-".join(wl)
            print(wl_show_name)
            apps = wl_show_name.split("-")

            #outputPathW = outputPath + "/" + wl_show_name
            #os.makedirs(os.path.abspath(outputPathW), exist_ok=True)

            appN = 0

            for app in apps:
                #dfN = pd.DataFrame(columns=['interval','app','HPKIL3:mean','MPKIL3:mean','IPC:mean'])
                #fig, ax = plt.subplots()
                print(app)
                # Dataframe for interval table
                wl_in_path = args.inputdir + "/" + wl_show_name + "/0" + str(appN) + "_" + app + "-intervalDataTable.csv"
                dfWay = pd.read_table(wl_in_path, sep=",")
                dfWay = dfWay[['interval','app','HPKIL3:mean','MPKIL3:mean','IPC:mean']]

                if dfN.empty:
                    dfN = dfWay
                else:
                    dfN = dfN.append(dfWay, ignore_index=True)

                appN = appN + 1

        dfN = dfN.set_index(['interval','app'])
        groups = dfN.groupby(level=[1])

        print(dfN)
        Y = dfN["MPKIL3:mean"].tolist()
        YI = dfN["IPC:mean"].tolist()
        X = dfN["HPKIL3:mean"].tolist()
        cols=pltcolor(YI)
        ax.scatter(X,Y,marker="x", color=cols, label=app)

        outputPathApp = outputPath + "/HPKI-MPKI-" + fileName + "-scatter.pdf"
        print(outputPathApp)
        plt.ylabel('MPKIL3')
        plt.xlabel('HPKIL3')
        plt.ylim(0,15)
        plt.xlim(0,45)
        plt.axvline(x=1, color='k', linestyle='--')
        plt.axhline(y=1, color='k', linestyle='--')
        ax.grid(True)

        # add custom legend
        green = mpatches.Patch(color='green', label='IPC > 1.9')
        brown = mpatches.Patch(color='brown', label='IPC 1.6 - 1.9')
        red = mpatches.Patch(color='red', label='IPC 1.3 - 1.6')
        blue = mpatches.Patch(color='blue', label='IPC 1.0 - 1.3')
        lightcoral = mpatches.Patch(color='lightcoral', label='IPC 0.7 - 1.0')
        dimgrey = mpatches.Patch(color='dimgrey', label='IPC < 0.7')
        plt.legend(handles=[green, brown, red, blue, lightcoral, dimgrey])

        # plot and save graph
        plt.show()
        plt.savefig(outputPathApp)
        plt.clf()
        plt.cla()
        plt.close()


# El main es crida des d'ací
if __name__ == "__main__":
    main()

