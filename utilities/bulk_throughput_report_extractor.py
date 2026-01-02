import os
import pandas as pd
import re

def parse_throughput_html(file_path):
    """Parses a single LANforge index-print.html for configuration and results."""
    try:
        # Load all tables from the HTML
        tables = pd.read_html(file_path)
        data = {'File Path': file_path}
        
        # Initialize default values to avoid 'N/A' if a table is missing
        fields = [
            'Station Increment', 'Total Download Rate', 'Total Upload Rate',
            'Per-Station Download Rate', 'Per-Station Upload Rate',
            'Observed Download (All Cx)', 'Observed Upload (All Cx)'
        ]
        for f in fields:
            data[f] = "N/A"

        for df in tables:
            # Convert whole table to string for easy keyword searching
            table_str = df.to_string()

            # 1. Extract Config Values (Increment, Total Rates)
            if "Station Increment:" in table_str:
                temp_df = df.set_index(0)
                if 'Station Increment:' in temp_df.index:
                    data['Station Increment'] = temp_df.loc['Station Increment:', 1]
                if 'Total Download Rate:' in temp_df.index:
                    data['Total Download Rate'] = temp_df.loc['Total Download Rate:', 1]
                if 'Total Upload Rate:' in temp_df.index:
                    data['Total Upload Rate'] = temp_df.loc['Total Upload Rate:', 1]

            # 2. Extract Requested Parameters (Per-Station Rates)
            elif "Per station:" in table_str:
                for _, row in df.iterrows():
                    row_list = row.astype(str).tolist()
                    row_content = " ".join(row_list)
                    if "Download Rate:" in row_content:
                        # Per station is usually index 2 in LANforge layout
                        data['Per-Station Download Rate'] = row_list[2]
                    if "Upload Rate:" in row_content:
                        data['Per-Station Upload Rate'] = row_list[2]

            # 3. Extract Observed Rates (All Cx)
            elif "All Cx:" in table_str:
                for _, row in df.iterrows():
                    row_list = row.astype(str).tolist()
                    row_content = " ".join(row_list)
                    if "Download Rate:" in row_content:
                        # All Cx is usually the last column
                        data['Observed Download (All Cx)'] = row_list[-1]
                    if "Upload Rate:" in row_content:
                        data['Observed Upload (All Cx)'] = row_list[-1]

        return data

    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return None

def main(parent_dir):
    all_results = []
    print(f"Scanning directory: {os.path.abspath(parent_dir)}")
    
    for root, dirs, files in os.walk(parent_dir):
        if "index-print.html" in files:
            file_path = os.path.join(root, "index-print.html")
            print(f"Found: {file_path}")
            result = parse_throughput_html(file_path)
            if result:
                all_results.append(result)

    if all_results:
        final_df = pd.DataFrame(all_results)
        
        # Define the exact column order for the CSV
        cols = [
            'File Path', 'Station Increment', 
            'Total Download Rate', 'Total Upload Rate', 
            'Per-Station Download Rate', 'Per-Station Upload Rate', 
            'Observed Download (All Cx)', 'Observed Upload (All Cx)'
        ]
        
        # Filter only for columns that exist
        existing_cols = [c for c in cols if c in final_df.columns]
        final_df = final_df[existing_cols]
        
        output_file = "Master_Throughput_Report.csv"
        final_df.to_csv(output_file, index=False)
        print(f"\nSuccess! Data from {len(all_results)} files saved to {output_file}")
    else:
        print("No valid data extracted.")

if __name__ == "__main__":
    main(".")
