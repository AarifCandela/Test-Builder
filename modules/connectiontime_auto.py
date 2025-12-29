import argparse
import pandas as pd
import subprocess
import sys
from collections import defaultdict
from tqdm import tqdm

# --- Argument Parser Setup ---
parser = argparse.ArgumentParser(
    prog='connectiontime_auto.py',
    formatter_class=argparse.RawTextHelpFormatter,
    epilog='''\
------------------------------------------------------------------------------------------------------------------------
EXAMPLE 1: Manually providing a client MAC list
  python connectiontime_auto.py -p capture.pcap -mac 00:0a:52:ed:58:d0 -o results -d "Password:SSID"

EXAMPLE 2: Auto-detecting all clients in the pcap
  python connectiontime_auto.py -p capture.pcap --auto-detect-clients -o results_auto -d "Password:SSID" --dhcpv6
------------------------------------------------------------------------------------------------------------------------
    ''',
    description='A reliable and robust script to analyze Wi-Fi connection timings.'
)

parser.add_argument('--pcap_file', '-p', help='Provide the pcap file path', required=True)
parser.add_argument('--client_mac_list', '-mac', nargs='+', help="Provide one or more client MAC addresses (required unless using --auto-detect-clients)")
parser.add_argument('--auto-detect-clients', action='store_true', help="Automatically find all client MACs from Association Requests in the pcap.")
parser.add_argument('--output_csv', '-o', help="Provide the name for the output CSV file", default='Roamtime_csv')
parser.add_argument('--decrypt_phrase', '-d', help="Provide the WPA key and SSID in the format '<wpa_key>:<ssid>'")
parser.add_argument('--dhcpv6', action='store_true', help="Enable calculation of time to first DHCPv6 Solicit message.")

args = parser.parse_args()

# --- Step 1: Discover Client MAC Addresses ---
transmitter_addresses_list = []
if args.auto_detect_clients:
    print(f"--- Auto-detecting client MACs from '{args.pcap_file}' ---")
    try:
        cmd_detect = ['tshark', '-r', args.pcap_file, '-Y', 'wlan.fc.type_subtype == 0', '-T', 'fields', '-e', 'wlan.sa']
        result = subprocess.run(cmd_detect, capture_output=True, text=True, check=True)
        detected_macs = result.stdout.strip().splitlines()
        if detected_macs:
            transmitter_addresses_list = sorted(list(set(detected_macs)))
            print(f"Found {len(transmitter_addresses_list)} unique client(s).")
        else:
            print("Could not find any client Association Requests in the pcap file.")
            sys.exit(0)
    except FileNotFoundError:
        print("Error: 'tshark' command not found. Is Wireshark installed and in your system's PATH?")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to detect clients: {e.stderr}")
        sys.exit(1)
elif args.client_mac_list:
    transmitter_addresses_list = args.client_mac_list
else:
    print("Error: You must provide a MAC list with --client_mac_list or use --auto-detect-clients.")
    sys.exit(1)

# --- Step 2: Process each client ---
df_data = []
for client_mac in tqdm(transmitter_addresses_list, desc="Processing Clients", unit="client"):
    client_mac_lower = client_mac.lower()
    timestamps = defaultdict(float)
    
    # This comprehensive filter gets all packets for a single client in one go.
    client_filter = (
        f"(wlan.fc.type_subtype == 5 && wlan.da == {client_mac_lower}) or "
        f"(wlan.fc.type_subtype == 1 && wlan.da == {client_mac_lower}) or "
        f"(wlan.fc.type_subtype == 11 && (wlan.da == {client_mac_lower} or wlan.ta == {client_mac_lower})) or "
        f"(eapol && (wlan.ra == {client_mac_lower} or wlan.ta == {client_mac_lower})) or "
        f"((dhcp or dhcpv6) && wlan.addr == {client_mac_lower})"
    )
    
    decryption_opts = []
    if args.decrypt_phrase:
        decryption_opts = ['-o', 'wlan.enable_decryption:TRUE', '-o', f'uat:80211_keys:"wpa-pwd","{args.decrypt_phrase}"']

    # The fields we need to identify each packet type from the text output
    fields = [
        '-e', 'frame.time_epoch', '-e', 'wlan.fc.type_subtype',
        '-e', 'wlan.da', '-e', 'wlan.ta', '-e', 'wlan.ra',
        '-e', 'wlan_rsna_eapol.keydes.msgnr',
        '-e', 'dhcp.option.dhcp', '-e', 'dhcpv6.msgtype'
    ]
    
    cmd_extract = ['tshark', '-r', args.pcap_file] + decryption_opts + ['-Y', client_filter, '-T', 'fields'] + fields
    
    try:
        result = subprocess.run(cmd_extract, capture_output=True, text=True, check=True)
        
        # Parse the simple tab-separated output
        for line in result.stdout.strip().splitlines():
            vals = line.split('\t')
            epoch_time, type_subtype_hex, da, ta, ra, eapol_nr, dhcp_type, dhcpv6_type = (vals + [''] * 8)[:8]

            if not epoch_time: continue
            time_float = float(epoch_time)
            
            type_subtype = int(type_subtype_hex, 16) if type_subtype_hex else -1

            if type_subtype == 5 and da == client_mac_lower: timestamps['probe_res'] = time_float
            elif type_subtype == 1 and da == client_mac_lower: timestamps['assoc_res'] = time_float
            elif type_subtype == 11:
                if ta == client_mac_lower and not timestamps['auth_req']: timestamps['auth_req'] = time_float
                if da == client_mac_lower: timestamps['auth_res'] = time_float
            
            if eapol_nr == '1' and ra == client_mac_lower and not timestamps['eapol_1']: timestamps['eapol_1'] = time_float
            if eapol_nr == '4' and ta == client_mac_lower: timestamps['eapol_4'] = time_float
            
            if dhcp_type == '1' and not timestamps['dhcp_discover']: timestamps['dhcp_discover'] = time_float
            if dhcp_type == '5': timestamps['dhcp_ack'] = time_float
            
            if dhcpv6_type == '1' and not timestamps['dhcpv6_solicit']: timestamps['dhcpv6_solicit'] = time_float

    except (subprocess.CalledProcessError, ValueError) as e:
        print(f"\nWarning: Could not process packets for {client_mac}. Error: {e}")
        continue
    
    def calc_diff(t1, t2):
        return f"{t2 - t1:.6f}" if t1 > 0 and t2 > 0 and t2 >= t1 else "-"

    row = {
        'Client MAC': client_mac,
        'Probe Req to Assoc Res (sec)': calc_diff(timestamps['probe_res'], timestamps['assoc_res']),
        'Auth Req to Assoc Res (sec)': calc_diff(timestamps['auth_req'], timestamps['assoc_res']),
        'Auth Res to Assoc Res (sec)': calc_diff(timestamps['auth_res'], timestamps['assoc_res']),
        '4-Way Handshake Time (sec)': calc_diff(timestamps['eapol_1'], timestamps['eapol_4']),
        'DHCPv4 Time (sec)': calc_diff(timestamps['dhcp_discover'], timestamps['dhcp_ack']),
    }
    if args.dhcpv6:
        row['Assoc Response to DHCPv6 Solicit (sec)'] = calc_diff(timestamps['assoc_res'], timestamps['dhcpv6_solicit'])
    
    df_data.append(row)

# --- Final DataFrame Creation and CSV Export ---
df = pd.DataFrame(df_data)
if not df.empty:
    df.insert(0, 'Sl.no.', range(1, len(df) + 1))
output_filename = f'{args.output_csv}.csv' if not args.output_csv.endswith('.csv') else args.output_csv
df.to_csv(output_filename, index=False)

print(f"\nProcessing complete. Data saved to '{output_filename}'")
