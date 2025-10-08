#!/usr/bin/env python3
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

def parse_ssl_logs(log_file_path):
    """
    Parses Zeek ssl.log entries to extract the connection UID, 4-tuple,
    SSL details, and JA4 and JA4S fingerprints.

    This script extracts the following fields based on a standard ssl.log header:
    - uid (Connection ID): Column 2 (Index 1)
    - id.orig_h (Source IP): Column 3 (Index 2)
    - id.orig_p (Source Port): Column 4 (Index 3)
    - id.resp_h (Destination IP): Column 5 (Index 4)
    - id.resp_p (Destination Port): Column 6 (Index 5)
    - version: Column 7 (Index 6)
    - cipher: Column 8 (Index 7)
    - server_name: Column 10 (Index 9)
    - ja4: Column 20 (Index 19)
    - ja4s: Column 21 (Index 20)

    Entries where both 'ja4' and 'ja4s' fields are empty are discarded.

    Args:
        log_file_path (str): The path to the Zeek ssl.log file. This script
                             assumes it is a plain text file (NOT gzipped).

    Returns:
        list of dict: A list where each dictionary represents a parsed entry
                      with keys 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                      'version', 'cipher', 'server_name', 'ja4', 'ja4s'.
    """
    parsed_entries = []
    
    # Field indices for clarity
    FIELD_INDICES = {
        'uid': 1,
        'src_ip': 2,
        'src_port': 3,
        'dst_ip': 4,
        'dst_port': 5,
        'version': 6,
        'cipher': 7,
        'server_name': 9,
        'ja4': 19,
        'ja4s': 20
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

                # Split by tabs
                fields = line.split('\t')
                
                # Ensure we have enough fields
                if len(fields) < 21:
                    print(f"Warning: Line {line_num} has only {len(fields)} fields, expected at least 21")
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
                version = clean_field(fields[FIELD_INDICES['version']])
                cipher = clean_field(fields[FIELD_INDICES['cipher']])
                server_name = clean_field(fields[FIELD_INDICES['server_name']])
                ja4 = clean_field(fields[FIELD_INDICES['ja4']])
                ja4s = clean_field(fields[FIELD_INDICES['ja4s']])

                # Only include entries that have at least one JA4 or JA4S value
                if ja4 or ja4s:
                    parsed_entries.append({
                        'uid': uid,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'version': version,
                        'cipher': cipher,
                        'server_name': server_name,
                        'ja4': ja4,
                        'ja4s': ja4s
                    })

    except FileNotFoundError:
        print(f"Error: Input file '{log_file_path}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading or parsing '{log_file_path}': {e}")
        return []
        
    return parsed_entries

def remove_duplicates(records):
    """
    Removes duplicate dictionaries from a list based on all keys.

    Args:
        records (list of dict): The list of dictionaries to filter.

    Returns:
        list of dict: A new list with all duplicate dictionaries removed.
    """
    unique_records_set = set()
    unique_records_list = []

    for record in records:
        record_tuple = tuple(record.items())
        if record_tuple not in unique_records_set:
            unique_records_set.add(record_tuple)
            unique_records_list.append(record)
    
    return unique_records_list

# --- How to use the script ---

if __name__ == "__main__":
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if len(sys.argv) > 1:
        log_file_path_ssl = sys.argv[1]
        
        if len(sys.argv) > 2:
            output_base_dir = sys.argv[2]
            print(f"Using custom output directory: {output_base_dir}")
        else:
            output_base_dir = "/mnt/zeek_logs/ja4/ja4s_ssl_hourly"
    else:
        log_file_path_ssl = "/mnt/zeek_logs/current/ssl.log"
        output_base_dir = "/mnt/zeek_logs/ja4/ja4s_ssl_hourly"

    os.makedirs(output_base_dir, exist_ok=True)

    parsed_records_ssl = parse_ssl_logs(log_file_path_ssl)
    
    if parsed_records_ssl:
        print(f"Parsed {len(parsed_records_ssl)} SSL entries from {log_file_path_ssl}")
        
        unique_records_ssl = remove_duplicates(parsed_records_ssl)
        num_duplicates_removed = len(parsed_records_ssl) - len(unique_records_ssl)
        
        print(f"Removed {num_duplicates_removed} duplicate records. Total unique records: {len(unique_records_ssl)}")

        output_csv_path_ssl = os.path.join(output_base_dir, f"parsed_ssl_logs_{timestamp}.csv")
        try:
            with open(output_csv_path_ssl, 'w', newline='') as csvfile:
                fieldnames = ['uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'version', 'cipher', 'server_name', 'ja4', 'ja4s']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for record in unique_records_ssl:
                    writer.writerow(record)
            print(f"SSL data successfully exported to CSV: {output_csv_path_ssl}")
        except IOError as e:
            print(f"Error saving SSL CSV file: {e}")

        output_json_path_ssl = os.path.join(output_base_dir, f"parsed_ssl_logs_{timestamp}.json")
        try:
            with open(output_json_path_ssl, 'w') as jsonfile:
                json.dump(unique_records_ssl, jsonfile, indent=4)
            print(f"SSL data successfully exported to JSON: {output_json_path_ssl}")
        except IOError as e:
            print(f"Error saving JSON file: {e}")

    else:
        print("No SSL records parsed. Check input file or parsing errors.")

