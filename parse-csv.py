
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
    index = res.index
    
    value_col_names = set(dataframes[0].columns.values.tolist()) - {'protocol', 'simd'}
    
    cols = {name: list() for name in value_col_names}
    for df in dataframes:
        for (col_name, series) in df.items():
            if col_name in value_col_names:
                cols[col_name].append(series)
    # find element-wise max
    for (col_name, series) in cols.items():
        max_vals = np.max(series, axis=0)
        res[col_name] = pd.Series(max_vals, index)
    
    return res

def group_by_simd(values, df):
    gr = list()
    for simd in values:
        gr.append(df[df['simd'] == simd])
    return gr

def format_throughput(tp):
    if tp != '-':
        return f'{tp:_}'.replace('_', ' ')
    else:
        return ''

def print_throughput(view):
    simd = float(list(view['simd'])[0])
    #make sure that the same simd value is used
    assert((view['simd'] == list(view['simd'])[0]).all())
    prep_avg = '-'
    prep_throughput = '-'
    
    online_avg = view['online-time'].mean()
    finalize_avg = view['finalize-time'].mean()
    online_throughput = math.floor(simd/(view['online-time'] + view['finalize-time']).mean())
    
    if list(view['pre-processing-time'])[0] != 0:
        prep_avg = view['pre-processing-time'].mean()
        prep_throughput = math.floor(simd/prep_avg)
        total_throughput = math.floor(simd/(view['pre-processing-time'] + view['online-time'] + view['finalize-time']).mean())
    else:
        total_throughput = online_throughput
    
    if prep_avg == '-':
        prep_avg = ''
    else:
        prep_avg = f'{prep_avg:4.2f}'
    
    prep_data_sent = view['pre-processing-bytes-sent-to-next'].max() + view['pre-processing-bytes-sent-to-prev'].max()
    prep_data_received = view['pre-processing-bytes-received-from-next'].max() + view['pre-processing-bytes-received-from-prev'].max()
    online_data_sent = view['online-bytes-sent-to-next'].max() + view['online-bytes-sent-to-prev'].max() + view['finalize-bytes-sent-to-next'].max() + view['finalize-bytes-sent-to-prev'].max()
    online_data_received = view['online-bytes-received-from-next'].max() + view['online-bytes-received-from-prev'].max()  + view['finalize-bytes-received-from-next'].max() + view['finalize-bytes-received-from-prev'].max()

    

    prep_comm = max(prep_data_sent, prep_data_received)
    if prep_comm > 0:
        prep_comm = f'{prep_comm/1000000:4.2f}'
    else:
        prep_comm = ''
    online_comm = max(online_data_sent, online_data_received)

    print(f'| {prep_avg} | {prep_comm} | {online_avg:4.2f} | {online_comm/1000000:4.2f} | {finalize_avg:4.2f} | {format_throughput(prep_throughput)} | {format_throughput(online_throughput)} | {format_throughput(total_throughput)}')

def print_latency(view):
    online_avg = (view['online-time'] + view['finalize-time']).mean()
    # print in ms
    print(f'| {online_avg*1000:3.0f}')

simd_values = list(set(dfs[0]['simd']))
simd_values.sort()

grouped_df = [group_by_simd(simd_values, df) for df in dfs]
grouped_df = [[grouped_df[j][i] for j in range(len(dfs))] for i in range(len(simd_values))]

for simd, group in zip(simd_values, grouped_df):
    df = find_max_values(group)
    protocols = list(set(df['protocol']))
    protocols.sort()

    print(f'### SIMD = {simd}\n')
    print('| Protocol | Prep Time | Prep Data (MB) | Online Time | Online Data (MB) | Finalize Time | Prep Throughput | Online Throughput | Total Throughput |')
    print('| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |')
    for prot in protocols:
        view = df[df['protocol'] == prot]
        print(f'| {prot} ', end='\t\t')
        print_throughput(view)
    print('\n')
    print('| Protocol | Latency (ms) |')
    print('| ----- | ----- |')
    for prot in protocols:
        view = df[df['protocol'] == prot]
        print(f'| {prot} ', end='\t\t')
        print_latency(view)
    print('\n\n')