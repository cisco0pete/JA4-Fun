# JA4+ Fun
This repo will be used to share my research regarding the JA4+ plugin on Zeek 7.0.8, Python3, Wireshark 4.4

All information obtained is directly from Foxio under there license. Please see: https://github.com/FoxIO-LLC/ja4?tab=readme-ov-file#running-ja4 for more information. This repository is for research purposes only. 

So far I have added the plugin for:

   Wireshark via Windows 11. 
   Wireshark for Ubuntu Raspberry Pi
   Python 3 on Ubuntu 

python3 ja4.py [pcap] [options] 

Usage
Command-line Arguments
positional arguments:
  pcap                      The pcap file to process

optional arguments:
  -h, --help                Show this help message and exit
  -key KEY                  The key file to use for decryption
  -v, --verbose             Verbose mode
  -J, --json                Output in JSON format
  --ja4                     Output JA4 fingerprints only
  --ja4s                    Output JA4S fingerprints only
  --ja4l                    Output JA4L-C/S fingerprints only
  --ja4h                    Output JA4H fingerprints only
  --ja4x                    Output JA4X fingerprints only
  --ja4ssh                  Output JA4SSH fingerprints only
  -r, --raw_fingerprint     Output raw fingerprint
  -o, --original_rendering  Output original rendering
  -f, --output [FILE]       Send output to file
  -s, --stream [STREAM]     Inspect a specific stream
