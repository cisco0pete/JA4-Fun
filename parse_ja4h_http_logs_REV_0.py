#!/usr/bin/env python3
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

def parse_http_logs(log_file_path):
    """
    Parses Zeek http.log entries to extract the connection UID, 4-tuple,
    HTTP details, and JA4H (HTTP Client) fingerprints.

    This script extracts the following fields based on a standard http.log header:
    - uid (Connection ID): Column 2 (Index 1)
    - id.orig_h (Source IP): Column 3 (Index 2)
    - id.orig_p (Source Port): Column 4 (Index 3)
    - id.resp_h (Destination IP): Column 5 (Index 4)
    - id.resp_p (Destination Port): Column 6 (Index 5)
    - method: Column 8 (Index 7)
    - host: Column 9 (Index 8)
    - uri: Column 10 (Index 9)
    - user_agent: Column 13 (Index 12)
    - status_code: Column 17 (Index 16)
    - ja4h: Column 31 (Index 30)

    Entries where the 'ja4h' field is empty are discarded.

    Args:
        log_file_path (str): The path to the Zeek http.log file. This script
                             assumes it is a plain text file (NOT gzipped).

    Returns:
        list of dict: A list where each dictionary represents a parsed entry
                      with keys 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                      'method', 'host', 'uri', 'user_agent', 'status_code', 'ja4h'.
    """
    parsed_entries = []
    
    # Field indices for clarity
    FIELD_INDICES = {
        'uid': 1,
        'src_ip': 2,
        'src_port': 3,
        'dst_ip': 4,
        'dst_port': 5,
        'method': 7,
        'host': 8,
        'uri': 9,
        'user_agent': 12,
        'status_code': 16,
        'ja4h': 30
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
                
                # Ensure we have enough fields (at least 31 for ja4h at index 30)
                if len(fields) < 31:
                    print(f"Warning: Line {line_num} has only {len(fields)} fields, expected at least 31")
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
                method = clean_field(fields[FIELD_INDICES['method']])
                host = clean_field(fields[FIELD_INDICES['host']])
                uri = clean_field(fields[FIELD_INDICES['uri']])
                user_agent = clean_field(fields[FIELD_INDICES['user_agent']])
                status_code = clean_field(fields[FIELD_INDICES['status_code']])
                ja4h = clean_field(fields[FIELD_INDICES['ja4h']])
                
                # Only include entries that have a ja4h value
                if ja4h:
                    parsed_entries.append({
                        'uid': uid,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'method': method,
                        'host': host,
                        'uri': uri,
                        'user_agent': user_agent,
                        'status_code': status_code,
                        'ja4h': ja4h
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
    # Using a set to keep track of unique records. Dictionaries are not hashable,
    # so we convert them to tuples of (key, value) pairs.
    unique_records_set = set()
    unique_records_list = []

    for record in records:
        # Convert dictionary to a tuple of items to make it hashable
        record_tuple = tuple(record.items())
        if record_tuple not in unique_records_set:
            unique_records_set.add(record_tuple)
            unique_records_list.append(record)
    
    return unique_records_list

# --- How to use the script ---

if __name__ == "__main__":
    # Get the current timestamp for unique filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determine log file path and output directory:
    # If an argument is provided, use it (for manual testing).
    # Otherwise, use the standard live Zeek http.log path.
    if len(sys.argv) > 1:
        log_file_path_http = sys.argv[1]
        
        # Check if a second argument (output directory) is provided
        if len(sys.argv) > 2:
            output_base_dir = sys.argv[2]
            print(f"Using custom output directory: {output_base_dir}")
        else:
            # Use same production directory even when testing
            output_base_dir = "/mnt/zeek_logs/ja4/ja4h_http_hourly"
    else:
        # Default path for the live Zeek http.log
        log_file_path_http = "/mnt/zeek_logs/current/http.log"
        # Default production output directory
        output_base_dir = "/mnt/zeek_logs/ja4/ja4h_http_hourly"

    # Create directory if it doesn't exist
    os.makedirs(output_base_dir, exist_ok=True)

    parsed_records_http = parse_http_logs(log_file_path_http)
    
    if parsed_records_http:
        print(f"Parsed {len(parsed_records_http)} HTTP entries from {log_file_path_http}")
        
        # Remove duplicate records
        unique_records_http = remove_duplicates(parsed_records_http)
        num_duplicates_removed = len(parsed_records_http) - len(unique_records_http)
        
        print(f"Removed {num_duplicates_removed} duplicate records. Total unique records: {len(unique_records_http)}")

        # Save to CSV file with timestamp in the specified directory
        output_csv_path_http = os.path.join(output_base_dir, f"parsed_http_logs_{timestamp}.csv")
        try:
            with open(output_csv_path_http, 'w', newline='') as csvfile:
                fieldnames = ['uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'method', 'host', 'uri', 'user_agent', 'status_code', 'ja4h']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for record in unique_records_http:
                    writer.writerow(record)
            print(f"HTTP data successfully exported to CSV: {output_csv_path_http}")
        except IOError as e:
            print(f"Error saving HTTP CSV file: {e}")

        # Save to JSON file with timestamp in the specified directory
        output_json_path_http = os.path.join(output_base_dir, f"parsed_http_logs_{timestamp}.json")
        try:
            with open(output_json_path_http, 'w') as jsonfile:
                json.dump(unique_records_http, jsonfile, indent=4)
            print(f"HTTP data successfully exported to JSON: {output_json_path_http}")
        except IOError as e:
            print(f"Error saving JSON file: {e}")

    else:
        print("No HTTP records parsed. Check input file or parsing errors.")

