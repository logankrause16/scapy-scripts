#!/usr/bin/env python3
"""
Host Discovery Script using TCP SYN Scan

This script is designed to discover live hosts on a network by sending a TCP SYN
packet to port 80 over a specified network range. If a host responds, it is
considered "alive". This method is useful for network reconnaissance and security
assessments.

DISCLAIMER:
    Use this script only on networks where you have explicit permission to perform
    such tests. Unauthorized scanning may be illegal and unethical.

Author: Bharath (github.com/yamakira)
"""

from scapy.all import IP, TCP, sr  # Import only the necessary components from Scapy.
import sys                      # For command-line argument handling.
import logging                  # To control logging and suppress unnecessary Scapy warnings.

# Suppress Scapy runtime warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def help_text():
    """
    Display usage instructions for the script and exit.

    This function is invoked if the user does not provide the required network range
    argument when running the script.
    """
    print("\nUsage:\n python hd_tcp_syn.py network_range\n")
    sys.exit(1)

def host_discovery(network_range):
    """
    Discover live hosts within a specified network range.

    This function sends TCP SYN packets to port 80 for every IP address in the provided
    network range. Responses indicate that the host is alive, and the source IP is printed.

    Parameters:
        network_range (str): The target network range in CIDR notation (e.g., "192.168.1.0/24")
    """
    # Send TCP SYN packets to the network range and capture responses.
    # The sr() function returns a tuple (answered, unanswered).
    ans, unans = sr(IP(dst=network_range)/TCP(dport=80, flags="S"), verbose=0, timeout=1)
    
    # For each answered packet, print the source IP (i.e., the live host).
    ans.summary(lambda s, r: r.sprintf("\n %IP.src% is alive\n"))

if __name__ == '__main__':
    # Check if the required network range argument is provided.
    if len(sys.argv) < 2:
        help_text()
    
    # Retrieve the network range from the command-line arguments.
    network_range = sys.argv[1]
    
    # Begin the host discovery process.
    host_discovery(network_range)
