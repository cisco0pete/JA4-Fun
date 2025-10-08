import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

def parse_tcp_logs(log_file_path):
    """
    Parses Zeek conn.log entries to extract the connection UID, 4-tuple,
    JA4T (TCP Client), and JA4TS (TCP Server Response) fingerprints.

    This script extracts the following fields based on a standard conn.log header:
    - uid (Connection ID): Column 2 (Index 1)
    - id.orig_h (Source IP): Column 3 (Index 2)
    - id.orig_p (Source Port): Column 4 (Index 3)
    - id.resp_h (Destination IP): Column 5 (Index 4)
    - id.resp_p (Destination Port): Column 6 (Index 5)
    - ja4t: Column 24 (Index 23)
    - ja4ts: Column 25 (Index 24)

    Entries where both 'ja4t' and 'ja4ts' fields are empty are discarded.

    Args:
        log_file_path (str): The path to the Zeek conn.log file. This script
                             assumes it is a plain text file (NOT gzipped).

    Returns:
        list of dict: A list where each dictionary represents a parsed entry
                      with keys 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                      'ja4t', and 'ja4ts'.
    """
    parsed_entries = []
    
    # Field indices for clarity
    FIELD_INDICES = {
        'uid': 1,
        'src_ip': 2,
        'src_port': 3,
        'dst_ip': 4,
        'dst_port': 5,
        'ja4t': 23,
        'ja4ts': 24
    }
    
    # Zeek's #empty_field is (empty), #unset_field is -
    empty_or_unset_values = {'(empty)', '-', ''}

    try:
        # Open the file as plain text
        with open(log_file_path, 'rt', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip header lines and empty lines
                if not line or line.startswith('#'):
                    continue

                # Split by tabs - much faster than regex
                fields = line.split('\t')
                
                # Ensure we have enough fields (at least 25 for ja4ts at index 24)
                if len(fields) < 25:
                    print(f"Warning: Line {line_num} has only {len(fields)} fields, expected at least 25")
                    continue

                # Helper function to clean empty/unset values
                def clean_field(field_value):
                    return '' if field_value in empty_or_unset_values else field_value

                # Extract and clean fields
                uid = clean_field(fields[FIELD_INDICES['uid']])
                src_ip = clean_field(fields[FIELD_INDICES['src_ip']])
                src_port = clean_field(fields[FIELD_INDICES['src_port']])
                dst_ip = clean_field(fields[FIELD_INDICES['dst_ip']])
                dst_port = clean_field(fields[FIELD_INDICES['dst_port']])
                ja4t = clean_field(fields[FIELD_INDICES['ja4t']])
                ja4ts = clean_field(fields[FIELD_INDICES['ja4ts']])

                # Check if at least one of the JA4 hash values is present
                if ja4t or ja4ts:
                    parsed_entries.append({
                        'uid': uid,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'ja4t': ja4t,
                        'ja4ts': ja4ts
                    })

    except FileNotFoundError:
        print(f"Error: Input file '{log_file_path}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading or parsing '{log_file_path}': {e}")
        return []
        
    return parsed_entries

# --- How to use the script ---

if __name__ == "__main__":
    # Get the current timestamp for unique filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determine log file path and output directory:
    # If an argument is provided, use it (for manual testing).
    # Otherwise, use the standard live Zeek conn.log path.
    if len(sys.argv) > 1:
        log_file_path_tcp = sys.argv[1]
        
        # Check if a second argument (output directory) is provided
        if len(sys.argv) > 2:
            output_base_dir = sys.argv[2]
            print(f"Using custom output directory: {output_base_dir}")
        else:
            # Use same production directory even when testing
            output_base_dir = "/mnt/zeek_logs/ja4/ja4t_ja4ts_hourly"
    else:
        # Default path for the live Zeek conn.log
        log_file_path_tcp = "/mnt/zeek_logs/current/conn.log"
        # Default production output directory
        output_base_dir = "/mnt/zeek_logs/ja4/ja4t_ja4ts_hourly"

    # Create directory if it doesn't exist
    os.makedirs(output_base_dir, exist_ok=True)

    parsed_records_tcp = parse_tcp_logs(log_file_path_tcp)

    if parsed_records_tcp:
        print(f"Parsed {len(parsed_records_tcp)} TCP entries from {log_file_path_tcp}")

        # Save to CSV file with timestamp in the specified directory
        output_csv_path_tcp = os.path.join(output_base_dir, f"parsed_tcp_logs_{timestamp}.csv")
        try:
            with open(output_csv_path_tcp, 'w', newline='') as csvfile:
                fieldnames = ['uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'ja4t', 'ja4ts']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for record in parsed_records_tcp:
                    writer.writerow(record)
            print(f"TCP data successfully exported to CSV: {output_csv_path_tcp}")
        except IOError as e:
            print(f"Error saving TCP CSV file: {e}")

        # Save to JSON file with timestamp in the specified directory
        output_json_path_tcp = os.path.join(output_base_dir, f"parsed_tcp_logs_{timestamp}.json")
        try:
            with open(output_json_path_tcp, 'w') as jsonfile:
                json.dump(parsed_records_tcp, jsonfile, indent=4)
            print(f"TCP data successfully exported to JSON: {output_json_path_tcp}")
        except IOError as e:
            print(f"Error saving JSON file: {e}")

    else:
        print("No TCP records parsed. Check input file or parsing errors.")
