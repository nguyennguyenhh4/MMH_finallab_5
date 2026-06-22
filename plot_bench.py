import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def main():
    sns.set_theme(style="whitegrid")
    
    raw_file = "benchmark_raw.csv"

    if not os.path.exists(raw_file):
        print("Missing benchmark_raw.csv. Run bench first.")
        return

    df_raw = pd.read_csv(raw_file)

    algos = df_raw['algo'].unique()
    ops = df_raw['operation'].unique()
    n_runs = df_raw['run_index'].max()

    for algo in algos:
        for op in ops:
            plt.figure(figsize=(10, 6))
            
            # Filter data for this algo and operation
            df_subset = df_raw[(df_raw['algo'] == algo) & (df_raw['operation'] == op)].copy()
            
            if not df_subset.empty:
                sns.lineplot(data=df_subset, x='run_index', y='time_ms', hue='size_label', marker='o')
                
                # Title formatting
                op_title = op.capitalize()
                algo_title = algo.upper()
                plt.title(f'{algo_title} {op_title} Latency over {n_runs} Runs', fontsize=14)
                plt.xlabel('Run Index', fontsize=12)
                plt.ylabel('Latency (Milliseconds)', fontsize=12)
                
                # Use log scale for Y-axis to separate lines better if they vary wildly
                # but if it's keygen, values might be very close. We'll use log scale anyway
                # to maintain consistency with previous labs.
                plt.yscale('log')
                
                plt.legend(title='Payload Size', bbox_to_anchor=(1.05, 1), loc='upper left')
                plt.tight_layout()
                
                # Output filename
                out_name = f"{algo}_{op}_latency.png".replace("-", "_")
                plt.savefig(out_name, dpi=300)
                print(f"Saved {out_name}")
                
            plt.close()

if __name__ == "__main__":
    main()
