#!/usr/bin/env python3
"""
A simple script to check the pattern in IPID generation on a target.

This script sends several SYN packets to a target (using TCP port 4444) and records the
IPID values from the responses. It then analyzes these IPID values to determine whether
the target's IPID generation is:
    - All zeros
    - Constant
    - Incremental
    - Randomized

For more information, refer to:
    http://nmap.org/book/idlescan.html

Author: Bharath (github.com/yamakira)
"""

from scapy.all import IP, TCP, sr1  # Import only the necessary functions from scapy.
import sys                        # For command-line argument handling.
import logging                    # To suppress unnecessary scapy warnings.

# Suppress scapy runtime warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def help_text():
    """
    Display usage instructions and exit the script.
    """
    print("\nUsage:\n python ipidseq.py target_ip\n")
    sys.exit()

def extract_ipids(target_ip):
    """
    Send SYN packets to the target and extract the IPID values from the responses.

    Parameters:
        target_ip (str): The IP address of the target.

    Returns:
        list: A list of IPID values extracted from the target's responses.
    """
    print("\nTarget => {}".format(target_ip))
    
    # Define the IP layer with the target's IP address.
    ip_layer = IP(dst=target_ip)
    
    # Define the TCP layer with destination port 4444 and the SYN flag set.
    tcp_layer = TCP(dport=4444, flags='S')
    
    # Combine the IP and TCP layers to form a SYN packet.
    syn_packet = ip_layer / tcp_layer

    ipids = []  # List to store the extracted IPID values.
    print("\n[+] Sending packets to the target")
    
    # Send 5 SYN packets and record the IPID from each response.
    for i in range(5):
        response = sr1(syn_packet, verbose=0)
        ipids.append(response.id)
    
    return ipids

def check_pattern(ipids):
    """
    Analyze the IPID values to determine the pattern of IPID generation.

    Parameters:
        ipids (list): A list of IPID values.

    Returns:
        str: A description of the IPID generation pattern:
             - "all zeros" if all IPID values are 0.
             - "constant" if all IPID values are identical.
             - "incremental" if each IPID increases by 1.
             - "randomized" if none of the above patterns match.
    """
    print("[+] Analyzing the IPID pattern")

    if all(v == 0 for v in ipids):
        return "all zeros"
    elif all(x == y for x, y in zip(ipids, ipids[1:])):
        return "constant"
    elif all(y - 1 == x for x, y in zip(ipids, ipids[1:])):
        return "incremental"
    else:
        return "randomized"

if __name__ == '__main__':
    # Ensure that the target IP is provided as a command-line argument.
    if len(sys.argv) < 2:
        help_text()
    
    # Retrieve the target IP from the command-line arguments.
    target_ip = sys.argv[1]
    
    # Extract IPID values from the target.
    ipids = extract_ipids(target_ip)
    
    # Analyze the extracted IPID values to determine the generation pattern.
    ipid_pattern = check_pattern(ipids)
    
    # Display the determined IPID generation pattern.
    print("[*] IPID generation pattern on {} is {}\n".format(target_ip, ipid_pattern))
