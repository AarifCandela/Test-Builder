#!/usr/bin/python3
import subprocess
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import argparse

# --- DEFAULTS ---
DEF_LFMGR = "localhost"
DEF_DURATION = 1
DEF_LOAD_STR = "500M"  # Default to 500 Mbps
PKT_SIZE_UDP = "1472"
PKT_SIZE_TCP = "MTU"

# List of tests to run
TEST_SUITE = [
    {"name": "UDP_Upload",   "proto": "udp", "dir": "UL", "pktsz": PKT_SIZE_UDP},
    {"name": "UDP_Download", "proto": "udp", "dir": "DL", "pktsz": PKT_SIZE_UDP},
    {"name": "TCP_Upload",   "proto": "tcp", "dir": "UL", "pktsz": PKT_SIZE_TCP},
    {"name": "TCP_Download", "proto": "tcp", "dir": "DL", "pktsz": PKT_SIZE_TCP},
]

def parse_load_to_bps(load_str):
    """
    Converts human readable strings (1G, 500M, 100k) into integer bits per second.
    """
    s = str(load_str).strip().lower()
    
    multiplier = 1
    value_str = s
    
    if s.endswith('g'):
        multiplier = 1_000_000_000
        value_str = s[:-1]
    elif s.endswith('m'):
        multiplier = 1_000_000
        value_str = s[:-1]
    elif s.endswith('k'):
        multiplier = 1_000
        value_str = s[:-1]
    elif s.endswith('b'):
        multiplier = 1
        value_str = s[:-1]

    try:
        return int(float(value_str) * multiplier)
    except ValueError:
        print(f"Error: Could not parse load '{load_str}'. Defaulting to 500M.")
        return 500_000_000

def generate_chart(csv_file, title):
    """Reads the CSV result and creates a visual throughput chart."""
    try:
        if not os.path.exists(csv_file):
            # Try appending .csv if not found (some LF scripts append it automatically)
            if os.path.exists(csv_file + ".csv"):
                csv_file = csv_file + ".csv"
            else:
                print(f"CSV not found for chart: {csv_file}")
                return

        df = pd.read_csv(csv_file)
        df.columns = df.columns.str.strip()
        
        # Check for required columns
        if 'ToS' in df.columns and 'Endpoint Rx Throughput' in df.columns:
            data = df[['ToS', 'Endpoint Rx Throughput']]
            
            plt.figure(figsize=(10, 6))
            # Standard colors for QoS
            colors = {'VO': 'red', 'VI': 'orange', 'BE': 'blue', 'BK': 'gray'}
            
            # Convert to Mbps for the Y-axis
            throughput_mbps = data['Endpoint Rx Throughput'] / 1000000
            
            bars = plt.bar(data['ToS'], throughput_mbps, color=[colors.get(x, 'blue') for x in data['ToS']])
            
            plt.xlabel('Access Category (ToS)')
            plt.ylabel('Throughput (Mbps)')
            plt.title(f'{title} - QoS Distribution')
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            
            # Add text labels on top of bars
            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval, f'{yval:.1f} M', ha='center', va='bottom')
                
            chart_name = f"{title}_chart.png"
            plt.savefig(chart_name)
            print(f"Chart generated: {chart_name}")
            plt.close()
        else:
            print(f"Chart skipped: Columns 'ToS' or 'Endpoint Rx Throughput' missing in {csv_file}")

    except Exception as e:
        print(f"Could not generate chart for {title}: {e}")

def run_suite(lfmgr, station, upstream, duration, load_str):
    # Convert load string (e.g., "1G") to integer bps
    load_bps = parse_load_to_bps(load_str)
    
    print(f"Starting QoS Suite on Station: {station} | Upstream: {upstream}")
    print(f"Manager: {lfmgr} | Duration: {duration}m")
    print(f"Target Load: {load_str} ({load_bps} bps)")
    print("="*60)

    for test in TEST_SUITE:
        print(f"\n>>> Running Test Case: {test['name']} ({test['proto']} {test['dir']})")
        
        outfile_base = f"/home/lanforge/Desktop/QoS_report/{test['name']}_report"
        outfile_xlsx = f"{outfile_base}.xlsx"
        outfile_csv = f"{outfile_base}.xlsx.csv"
        
        cx_args = []
        # Order of QoS buckets
        tos_list = ["BK", "BE", "VI", "VO"]
        
        for tos in tos_list:
            # Assign load based on direction
            if test['dir'] == "UL":
                speed_ul = load_bps
                speed_dl = 0
            else:
                speed_ul = 0
                speed_dl = load_bps
            
            # Argument format: "NA station NA upstream proto pktsz ul dl tos"
            # NA means: Don't change Radio/Mode
            cx_str = f"NA {station} NA {upstream} {test['proto']} {test['pktsz']} {speed_ul} {speed_dl} {tos}"
            cx_args.extend(["--cx", cx_str])

        # Build the command
        cmd = [
            "./lf_tos_plus_test.py",
            "--lfmgr", lfmgr,
            "--outfile", outfile_xlsx,
            "--dur", str(duration)
        ] + cx_args

        try:
            # Execute the LANforge script
            subprocess.run(cmd, check=True)
            print(f"Completed {test['name']}.")
            
            # Generate chart
            generate_chart(outfile_csv, test['name'])
                
        except subprocess.CalledProcessError as e:
            print(f"Error running {test['name']}: {e}")

    print("\n" + "="*60)
    print("Test Suite Completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run QoS Test Suite (UL/DL, TCP/UDP)")
    
    # Required Arguments
    parser.add_argument("--station", required=True, help="The Station Resource (e.g., 1.sta0000)")
    parser.add_argument("--upstream", required=True, help="The Upstream Resource (e.g., 1.eth1)")
    
    # Optional Arguments
    parser.add_argument("--lfmgr", default=DEF_LFMGR, help=f"LANforge Manager IP (default: {DEF_LFMGR})")
    parser.add_argument("--duration", type=float, default=DEF_DURATION, help=f"Duration in minutes (default: {DEF_DURATION})")
    
    # Load Argument (String)
    parser.add_argument("--load", type=str, default=DEF_LOAD_STR, help=f"Intended Load (e.g., 1G, 500M, 100k). Default: {DEF_LOAD_STR}")

    args = parser.parse_args()
    
    run_suite(args.lfmgr, args.station, args.upstream, args.duration, args.load)