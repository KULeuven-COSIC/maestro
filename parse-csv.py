
import pandas as pd
import sys
import math
import numpy as np

if len(sys.argv) != 4:
    print(f'Usage: {sys.argv[0]} <file1.csv> <file2.csv> <file3.csv>')
    sys.exit(-1)


filenames = sys.argv[1:4]
dfs = [pd.read_csv(f) for f in filenames]


def find_max_values(dataframes):
    res = dataframes[0].copy()
    
    value_col_names = set(dataframes[0].columns.values.tolist()) - {'protocol'}
    
    cols = {name: list() for name in value_col_names}
    for df in dataframes:
        for (col_name, series) in df.items():
            if col_name in value_col_names:
                cols[col_name].append(series)
    
    # find element-wise max
    for (col_name, series) in cols.items():
        max_vals = np.max(series, axis=0)
        res[col_name] = pd.Series(max_vals)
    
    return res

df = find_max_values(dfs)

def print_throughput(view):
    simd = float(list(view['simd'])[0])
    #make sure that the same simd value is used
    assert((view['simd'] == list(view['simd'])[0]).all())
    prep_avg = '-'
    prep_throughput = '-'
    if list(view['pre-processing-time'])[0] != 0:
        prep_avg = view['pre-processing-time'].mean()
        prep_throughput = math.floor(simd/prep_avg)
    online_avg = view['online-time'].mean()
    online_throughput = math.floor(simd/online_avg)
    
    prep_data_sent = view['pre-processing-bytes-sent-to-next'].max() + view['pre-processing-bytes-sent-to-prev'].max()
    prep_data_received = view['pre-processing-bytes-received-from-next'].max() + view['pre-processing-bytes-received-from-prev'].max()
    online_data_sent = view['online-bytes-sent-to-next'].max() + view['online-bytes-sent-to-prev'].max()
    online_data_received = view['online-bytes-received-from-next'].max() + view['online-bytes-received-from-prev'].max()
    print(f'Prep. Throughput: {prep_throughput}\tOnline Throughput: {online_throughput}\tPrep. Time: {prep_avg}s\tOnline Time: {online_avg}s\tPrep. Data: {max(prep_data_sent, prep_data_received)} byte\tOnline Data: {max(online_data_sent, online_data_received)} byte')

protocols = list(set(df['protocol']))
protocols.sort()

print(f'SIMD = {list(df["simd"])[0]}')
for prot in protocols:
    view = df[df['protocol'] == prot]
    print(prot, end='\t\t')
    print_throughput(view)