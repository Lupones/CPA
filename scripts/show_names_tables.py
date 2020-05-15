import argparse
import numpy as np
import os
import pandas as pd
import re
import scipy.stats
import sys
import yaml
import glob

def main():
    parser = argparse.ArgumentParser(description='Process results of workloads by intervals.')
    parser.add_argument('-w', '--workloads', required=True, help='.yaml file where the list of workloads is found.')
    parser.add_argument('-od', '--outputdir', default='./output', help='Directory where output files will be placed')
    parser.add_argument('-id', '--inputdir', default='./data', help='Directory where input are found')
    parser.add_argument('-n', '--names', action='append', default=[], help='Names of columns we want to generate tables')
    parser.add_argument('-p', '--policies', action='append', default=[], help='Policies we want to show results of. Options: noPart,criticalAware,criticalAwareV2,dunn.')
    parser.add_argument('-dp', '--defaultPolicy', default='noPart', help='Default policy used as a basis to compare the other ones.')

    args = parser.parse_args()

    # dictionary with names of headers of data we want to include in the tables
    dictNames = {}

    # include names in dictionary
    for name in args.names:
        dictNames[name] = "df_"+name

    with open(args.workloads, 'r') as f:
        workloads = yaml.load(f)

    outputPath= os.path.abspath(args.outputdir)

    columns = ['Workload_ID','Workload']
    for p in args.policies:
    	columns.append(p)

    index = range(0, 34)

    # create data frame for each name
    for name in args.names:
        df = dictNames[name]
        df = pd.DataFrame(columns=columns, index = index)
        df['Workload_ID'] = range(1, 35)
        dictNames[name] = df

    # add values
    phase_changes = 0
    CLOS_changes = 0

    for policy in args.policies:
        numW = 0
        print(policy)
        for wl_id, wl in enumerate(workloads):

            #name of the file with raw data
            wl_show_name = "-".join(wl)
            print(wl_show_name)

            for name in args.names:
                df = dictNames[name]
                df.ix[numW,'Workload'] = wl_show_name

                if name == "interval" or "power" in name:
                    wl_name = args.inputdir + "/" + policy +  "/data-agg/" + wl_show_name + "_tot.csv"
                else:
                    wl_name = args.inputdir + "/" + policy +  "/data-agg/" + wl_show_name + "_fin.csv"

                dfworkload = pd.read_table(wl_name, sep=",")

                if name == "interval" or "power" in name:
                    df.ix[numW,policy] = dfworkload[name+':mean'].max()

                    if policy == "CPA_0.2":
                        print(dfworkload[["app","phase_changes:mean","CLOS_changes:mean"]])
                        phase_changes = phase_changes + dfworkload["phase_changes:mean"].sum()
                        CLOS_changes = CLOS_changes + dfworkload["CLOS_changes:mean"].sum()
                        print(dfworkload["CLOS_changes:mean"].sum())

                    #df.ix[numW,policy+':std'] = dfworkload[name+':std'].max()
                elif name == "geoipc":
                    df.ix[numW, policy] = scipy.stats.gmean(dfworkload['ipc:mean'],axis=0)
                else:
                    df.ix[numW,policy] = dfworkload[name+':mean'].mean()
                    #df.ix[numW,policy+':std'] = dfworkload[name+':std'].mean()

                dictNames[name] = df

            numW = int(numW) + 1


    # generate tables
    for name in args.names:

        df = dictNames[name]
        show_name = name.replace("/", "-")
        for policy in args.policies:
            if policy != args.defaultPolicy:
                if name == "geoipc":
                    df["%gain"+policy+":mean"] = ((df[policy] / df[args.defaultPolicy]) - 1) * 100
                elif name == "ipc":
                    df["%gain"+policy+":mean"] = ((df[policy] / df[args.defaultPolicy]) - 1) * 100
                else:
                    df["%gain"+policy+":mean"] = ((df[args.defaultPolicy] / df[policy]) - 1) * 100

        print(name)
        for policy in args.policies:
            if policy != args.defaultPolicy:
                print('{}: {:.2f}'.format(policy,df["%gain"+policy+":mean"].mean()))
        print(" ")

        # save tables
        df  = df.set_index(['Workload_ID'])
        outputPathPolicy = outputPath + "/" + show_name + "table.csv"
        df.to_csv(outputPathPolicy, sep=',')
        dictNames[name] = df

    CLOS_changes = CLOS_changes/31
    phase_changes = phase_changes/248
    print("-----------")
    print('phase_changes = {:.2f}'.format(phase_changes))
    print('CLOS_changes = {:.2f}'.format(CLOS_changes))
    print("-----------")


if __name__ == "__main__":
    main()
