import argparse
import pandas as pd
import subprocess
import sys
import os
from collections import defaultdict
from tqdm import tqdm

# --- Argument Parser Setup ---
parser = argparse.ArgumentParser(
    prog='connectiontime_advanced.py',
    formatter_class=argparse.RawTextHelpFormatter,
    description='Advanced Wi-Fi connection timing analyzer with anomaly detection.'
)

parser.add_argument('--pcap_file', '-p', help='Provide the pcap file path', required=True)
parser.add_argument('--client_mac_list', '-mac', nargs='+', help="Provide client MACs (required unless --auto-detect-clients is used)")
parser.add_argument('--auto-detect-clients', action='store_true', help="Automatically find all client MACs from Association Requests.")
parser.add_argument('--output_csv', '-o', help="Output CSV file name", default='Roamtime_Analysis')
parser.add_argument('--decrypt_phrase', '-d', help="WPA key and SSID in format '<wpa_key>:<ssid>'")
parser.add_argument('--dhcpv6', action='store_true', help="Enable calculation of time to first DHCPv6 Solicit message.")
parser.add_argument('--keep-temp', action='store_true', help="Do not delete the optimized temp pcap file.")

args = parser.parse_args()

# --- Step 1: Optimization (Pre-filtering) ---
temp_pcap = "optimized_temp.pcap"
print(f"--- Optimizing: Creating a filtered temporary file from '{args.pcap_file}' ---")

# We include type 12 (Deauth) explicitly now
optimization_filter = (
    "wlan.fc.type_subtype in {0,1,5,11,12} || "
    "eapol || "
    "dhcp || "
    "dhcpv6"
)

try:
    cmd_optimize = [
        'tshark', '-r', args.pcap_file, 
        '-Y', optimization_filter, 
        '-w', temp_pcap
    ]
    if args.decrypt_phrase:
        cmd_optimize += ['-o', 'wlan.enable_decryption:TRUE', '-o', f'uat:80211_keys:"wpa-pwd","{args.decrypt_phrase}"']
        
    subprocess.run(cmd_optimize, check=True)
except Exception as e:
    print(f"Error during optimization: {e}")
    sys.exit(1)

# --- Step 2: Client Detection ---
transmitter_addresses_list = []
if args.auto_detect_clients:
    try:
        cmd_detect = ['tshark', '-r', temp_pcap, '-Y', 'wlan.fc.type_subtype == 0', '-T', 'fields', '-e', 'wlan.sa']
        result = subprocess.run(cmd_detect, capture_output=True, text=True, check=True)
        detected = result.stdout.strip().splitlines()
        if detected:
            transmitter_addresses_list = sorted(list(set(detected)))
            print(f"Found {len(transmitter_addresses_list)} unique client(s).")
        else:
            print("No clients found.")
            sys.exit(0)
    except:
        sys.exit(1)
elif args.client_mac_list:
    transmitter_addresses_list = args.client_mac_list
else:
    sys.exit(1)

# --- Step 3: Process Clients with Logic Tracing ---
df_data = []

for client_mac in tqdm(transmitter_addresses_list, desc="Analyzing Clients", unit="client"):
    client_mac_lower = client_mac.lower()
    
    # We store ALL occurrences of events in lists to analyze later
    events = defaultdict(list) 
    
    # Filter for this specific client
    # Note: For Deauth (12), we want to see if the client sent it OR received it (AP sent it)
    client_filter = (
        f"(wlan.addr == {client_mac_lower}) && "
        f"(wlan.fc.type_subtype in {{1,5,11,12}} || eapol || dhcp || dhcpv6)"
    )

    decryption_opts = []
    if args.decrypt_phrase:
        decryption_opts = ['-o', 'wlan.enable_decryption:TRUE', '-o', f'uat:80211_keys:"wpa-pwd","{args.decrypt_phrase}"']

    fields = [
        '-e', 'frame.time_epoch', 
        '-e', 'wlan.fc.type_subtype',
        '-e', 'wlan.sa', # Source Address (Transmitter)
        '-e', 'wlan.da', # Destination
        '-e', 'wlan_rsna_eapol.keydes.msgnr',
        '-e', 'dhcp.option.dhcp', 
        '-e', 'dhcpv6.msgtype'
    ]
    
    cmd = ['tshark', '-r', temp_pcap] + decryption_opts + ['-Y', client_filter, '-T', 'fields'] + fields
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        for line in res.stdout.strip().splitlines():
            parts = line.split('\t')
            epoch, ftype_hex, sa, da, eapol_nr, dhcp_t, dhcpv6_t = (parts + [''] * 8)[:7]
            
            if not epoch: continue
            t = float(epoch)
            ftype = int(ftype_hex, 16) if ftype_hex else -1
            
            # --- Event Collection ---
            if ftype == 5 and da == client_mac_lower: 
                events['probe_res'].append(t)
            elif ftype == 1 and da == client_mac_lower: 
                events['assoc_res'].append(t)
            elif ftype == 11:
                if da == client_mac_lower: events['auth_res'].append(t)
                if sa == client_mac_lower: events['auth_req'].append(t)
            elif ftype == 12: # Deauthentication
                # If SA is client, client sent deauth. Else AP sent it.
                initiator = 'Client' if sa == client_mac_lower else 'AP'
                events['deauth'].append({'time': t, 'src': initiator})
            
            # EAPOL
            if eapol_nr == '1': events['eapol_1'].append(t)
            if eapol_nr == '4': events['eapol_4'].append(t)
            
            # DHCP
            if dhcp_t == '1': events['dhcp_disc'].append(t)
            if dhcp_t == '5': events['dhcp_ack'].append(t)
            
            if dhcpv6_t == '1': events['dhcpv6_sol'].append(t)

    except Exception as e:
        print(f"Error processing {client_mac}: {e}")
        continue

    # --- LOGIC: Trace Backwards from Success ---
    # 1. Find the Anchor: The First DHCP ACK
    # If no ACK, use the last Discover. If no Discover, use last EAPOL 4.
    
    final_timestamps = defaultdict(float)
    
    # Helper to find the last timestamp in a list that is SMALLER than a reference
    def get_last_before(ts_list, ref_time):
        valid = [x for x in ts_list if x < ref_time]
        return valid[-1] if valid else 0.0

    # A. DHCP ACK
    t_dhcp_ack = events['dhcp_ack'][0] if events['dhcp_ack'] else 0.0
    final_timestamps['dhcp_ack'] = t_dhcp_ack
    
    # Define our "End of Connection" anchor for tracing back
    trace_anchor = t_dhcp_ack if t_dhcp_ack > 0 else 9999999999.0

    # B. DHCP Discover
    # We want the Discover closest to the Ack (or just the last one if no Ack)
    t_dhcp_disc = get_last_before(events['dhcp_disc'], trace_anchor)
    final_timestamps['dhcp_discover'] = t_dhcp_disc
    
    if t_dhcp_disc > 0: trace_anchor = t_dhcp_disc # Update anchor to find EAPOL before Disc

    # C. EAPOL 4
    # We want the EAPOL 4 closest to the Discover
    t_eapol_4 = get_last_before(events['eapol_4'], trace_anchor)
    final_timestamps['eapol_4'] = t_eapol_4
    
    if t_eapol_4 > 0: trace_anchor = t_eapol_4 # Update anchor to find EAPOL 1 before EAPOL 4

    # D. EAPOL 1
    t_eapol_1 = get_last_before(events['eapol_1'], trace_anchor)
    final_timestamps['eapol_1'] = t_eapol_1
    
    # E. Standard Assoc/Auth (Usually simply the first ones are valid, or last ones before EAPOL)
    # We'll take the ones closest to our EAPOL 1 anchor
    if t_eapol_1 > 0: trace_anchor = t_eapol_1
    
    final_timestamps['assoc_res'] = get_last_before(events['assoc_res'], trace_anchor)
    # Fallback: if no EAPOL, maybe open auth? use Association as anchor
    if final_timestamps['assoc_res'] == 0 and events['assoc_res']: 
         final_timestamps['assoc_res'] = events['assoc_res'][-1]
         
    anchor_assoc = final_timestamps['assoc_res'] if final_timestamps['assoc_res'] > 0 else 9999999999.0
    final_timestamps['auth_res'] = get_last_before(events['auth_res'], anchor_assoc)
    final_timestamps['auth_req'] = get_last_before(events['auth_req'], anchor_assoc)
    final_timestamps['probe_res'] = get_last_before(events['probe_res'], anchor_assoc)

    # --- Anomaly Detection / Comments ---
    comments = []
    
    # 1. Check for multiple attempts
    if len(events['eapol_1']) > 1:
        comments.append(f"{len(events['eapol_1'])}x 4-Ways")
    if len(events['dhcp_disc']) > 1:
        comments.append(f"{len(events['dhcp_disc'])}x DHCP Discovers")
        
    # 2. Check for Deauths in the middle of the flow
    # Flow starts at Auth Req/Assoc and ends at DHCP Ack
    start_flow = final_timestamps['auth_req'] if final_timestamps['auth_req'] > 0 else final_timestamps['assoc_res']
    end_flow = t_dhcp_ack if t_dhcp_ack > 0 else t_eapol_4
    
    deauths_in_flow = [d for d in events['deauth'] if start_flow < d['time'] < end_flow]
    if deauths_in_flow:
        ap_deauth = sum(1 for d in deauths_in_flow if d['src'] == 'AP')
        cl_deauth = sum(1 for d in deauths_in_flow if d['src'] == 'Client')
        if ap_deauth: comments.append(f"Deauth by AP ({ap_deauth})")
        if cl_deauth: comments.append(f"Deauth by Client ({cl_deauth})")

    # 3. Check for specific failure patterns
    if t_eapol_1 > 0 and t_eapol_4 == 0:
        comments.append("Failed 4-Way (Timeout)")
    if t_dhcp_disc > 0 and t_dhcp_ack == 0:
        comments.append("DHCP Fail (No Ack)")

    # --- Calculations ---
    def diff(t1, t2):
        if t1 > 0 and t2 > 0 and t2 >= t1:
            return f"{t2 - t1:.6f}"
        return "-"

    row = {
        'Client MAC': client_mac,
        'Auth/Assoc Time (sec)': diff(final_timestamps['auth_req'], final_timestamps['assoc_res']),
        '4-Way Handshake (sec)': diff(final_timestamps['eapol_1'], final_timestamps['eapol_4']),
        '4-Way to DHCP Disc (sec)': diff(final_timestamps['eapol_4'], final_timestamps['dhcp_discover']),
        'DHCP DORA Time (sec)': diff(final_timestamps['dhcp_discover'], final_timestamps['dhcp_ack']),
        'Total Time (Assoc->IP) (sec)': diff(final_timestamps['assoc_res'], final_timestamps['dhcp_ack']),
        'Comments/Anomalies': ", ".join(comments) if comments else "Clean"
    }
    df_data.append(row)

# --- Save ---
if not args.keep_temp and os.path.exists(temp_pcap):
    os.remove(temp_pcap)

df = pd.DataFrame(df_data)
if not df.empty:
    df.insert(0, 'Sl.no.', range(1, len(df) + 1))
    
output_filename = f'{args.output_csv}.csv' if not args.output_csv.endswith('.csv') else args.output_csv
df.to_csv(output_filename, index=False)
print(f"\nProcessing complete. Data saved to '{output_filename}'")
