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
from matplotlib.lines import Line2D

matplotlib.rcParams.update({'font.size': 20})
#plt.style.use('tableau-colorblind10')

def main():
    parser = argparse.ArgumentParser(description='Process results of workloads by intervals.')
    parser.add_argument('-od', '--outputdir', default='./output', help='Directory where output files will be placed')
    parser.add_argument('-id', '--inputdir', default='./data', help='Directory where input are found')
    parser.add_argument('-fn', '--fileName', help='Files containing lists of apps or workloads names.')
    parser.add_argument('-m', '--metric', action='append', default=[], help='Metrics.')
    parser.add_argument('-p', '--policy', action='append', default=[], help='Policies.')
    args = parser.parse_args()

    outputPath = os.path.abspath(args.outputdir)
    os.makedirs(os.path.abspath(outputPath), exist_ok=True)

    colors = itertools.cycle(['#ABABAB', '#FF800E', '#006BA4'])

    with open(args.fileName, 'r') as f:
        workloads = yaml.load(f)


    for metric in args.metric:
        print(metric)

        hand = []

        wl_in_path = args.inputdir + "/" + metric + "table.csv"
        print( wl_in_path)
        dfMetric = pd.read_table(wl_in_path, sep=",")

        listY = list(args.policy)
        length = len(listY)
        for i in range(length):
            cc = next(colors)
            patch = mpatches.Patch(color=cc, label=listY[i])
            hand.append(patch)

            listY[i] = "%gain"+listY[i]+":mean"
            #listY[i] = "%gain"+listY[i]
            dfMetric[listY[i]] = dfMetric[listY[i]] / 100

        ax = dfMetric.plot.bar(x='Workload_ID', y=listY, rot='horizontal', color=['#ABABAB' '#FF800E', '#006BA4'], fontsize=20,figsize=(14,5), width=0.70)

        ax.set_xlabel("# Mix", fontsize=20)
        ax.set_xticks(np.arange(0,31,1), )
        for label in ax.get_xaxis().get_ticklabels()[::2]:
            label.set_visible(False)
        ax.set_xlim(-1,31)

        #if metric == "geoipc":
        #    ax.set_ylabel("GeoMean IPC Improvement (%)", fontsize=20)
        #elif metric == "interval":
        #    ax.set_ylabel("TT Improvement (%)", fontsize=20)
        #elif metric == "antt":
        #    ax.set_ylabel("ANTT Improvement (%)", fontsize=20)

        vals = ax.get_yticks()
        ax.set_yticklabels(['{:.0%}'.format(x) for x in vals])

        ax.legend(handles=hand, prop={'size': 20}, loc='upper center', bbox_to_anchor=(0.5, -0.19), ncol=3, frameon=False, fontsize=20)

        ax.grid(True)
        #ax.yaxis.grid()
        print(outputPath + "/" + metric + ".pdf")
        fig = ax.get_figure()
        fig.savefig(outputPath + "/" + metric + ".pdf", bbox_inches='tight')
        plt.close()




# El main es crida des d'ací
if __name__ == "__main__":
    main()

