#!/usr/bin/env python3
"""
all_devices.py

This script analyzes a pcap (packet capture) file to extract and print a list of unique IP addresses
present in the captured network traffic. It uses the Scapy library to read and process the packets.
Both source and destination IP addresses are extracted and printed as soon as they are found.

Usage:
    python3 all_devices.py path_to_pcap

Dependencies:
    - Python 3.x
    - Scapy (install via: pip install scapy)

Functionality:
    - Reads a pcap file using Scapy's rdpcap function.
    - Iterates over each packet and checks for the presence of an IP layer.
    - Extracts and prints unique source and destination IP addresses.
    - Displays a final list of all unique IP addresses found.
"""

import sys
from scapy.all import rdpcap, IP

def help_text():
    """
    Displays the usage instructions for the script and exits the program.

    This function is called when the required pcap file path argument is missing.
    """
    print("Usage: python3 all_devices.py path_to_pcap")
    sys.exit(1)

def extract_machine_names(pcap_file):
    """
    Extracts unique IP addresses from the provided pcap file.

    Parameters:
        pcap_file (str): The file path to the pcap file to analyze.

    Returns:
        list: A list of unique IP addresses found in the pcap file.

    Process:
        1. Reads all packets from the given pcap file using rdpcap.
        2. Iterates over each packet and checks if the packet contains an IP layer.
        3. For packets with an IP layer:
           - Checks the source IP address; if it is not already in the list, adds it and prints it.
           - Checks the destination IP address; if it is not already in the list, adds it and prints it.
    """
    machines = []  # List to store unique IP addresses
    packets = rdpcap(pcap_file)  # Read packets from the provided pcap file

    # Iterate over each packet in the capture file
    for packet in packets:
        # Ensure the packet contains an IP layer to prevent processing errors
        if IP in packet:
            # Process the source IP address if it hasn't been encountered before
            if packet[IP].src not in machines:
                machines.append(packet[IP].src)
                print(len(machines), packet[IP].src)
            # Process the destination IP address if it hasn't been encountered before
            if packet[IP].dst not in machines:
                machines.append(packet[IP].dst)
                print(len(machines), packet[IP].dst)
    
    return machines

if __name__ == '__main__':
    # Verify that the user has provided the pcap file path as a command-line argument
    if len(sys.argv) < 2:
        help_text()  # Show help text and exit if no file path is provided

    # The first argument is the path to the pcap file
    pcap_file = sys.argv[1]

    # Extract and print the unique IP addresses from the provided pcap file
    print("\nList of all the machines in pcap =>", extract_machine_names(pcap_file), "\n")
