import json
import os
import argparse
from datetime import datetime

def parse_x509_log(log_file_path):
    """
    Parses a Zeek x509.log file and yields JSON objects.
    """
    try:
        with open(log_file_path, 'r') as f:
            # Read the header to get field names
            header_lines = [next(f) for _ in range(8)]
            field_names = header_lines[-1].strip().split('\t')

            for line in f:
                if line.startswith('#'):
                    continue  # Skip comment lines

                values = line.strip().split('\t')
                log_entry = dict(zip(field_names, values))

                # Construct the desired JSON structure
                json_entry = {
                    "uid": log_entry.get("uid"),
                    "log_type": "x509_log",
                    "fuid": log_entry.get("fuid"),
                    "id": {
                        "orig_h": log_entry.get("id.orig_h"),
                        "resp_h": log_entry.get("id.resp_h")
                    },
                    "cert_info": {
                        "ja4x": log_entry.get("ja4x"),
                        "version": log_entry.get("version"),
                        "serial": log_entry.get("serial"),
                        "subject": log_entry.get("subject"),
                        "issuer": log_entry.get("issuer"),
                        "validity": {
                            "not_before": log_entry.get("validity.not_before"),
                            "not_after": log_entry.get("validity.not_after")
                        },
                        "key_type": log_entry.get("key_type"),
                        "signature_algorithm": log_entry.get("sig_alg")
                    }
                }
                yield json_entry
    except FileNotFoundError:
        print(f"Error: The file '{log_file_path}' was not found.", file=os.sys.stderr)
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=os.sys.stderr)
        return

def main():
    parser = argparse.ArgumentParser(description="Parse Zeek x509.log into a JSON file with JA4X fingerprints.")
    parser.add_argument("--input_file", default="/mnt/zeek_logs/current/x509.log", help="Path to the Zeek x509.log file.")
    
    args = parser.parse_args()
    
    # Hardcode the output directory as requested
    output_dir = "/mnt/zeek_logs/ja4/ja4x_x509_hourly"

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Generate a timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"parsed_x506_logs_{timestamp}.json"
    output_path = os.path.join(output_dir, output_filename)

    parsed_logs = list(parse_x509_log(args.input_file))
    
    if parsed_logs:
        with open(output_path, 'w') as f:
            json.dump(parsed_logs, f, indent=2)

if __name__ == "__main__":
    main()
