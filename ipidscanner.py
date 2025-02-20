#!/usr/bin/env python3
"""
Idle Scan Script

This script performs an idle scan to determine the state of a port on a victim host by leveraging
a zombie host. It exploits the predictable IPID sequence of the zombie host to infer whether a port
on the victim is open or closed. For more information on idle scans, see:
http://nmap.org/book/idlescan.html

Author: Bharath (github.com/yamakira)
"""

from scapy.all import IP, TCP, sr1, send  # Import required Scapy functions and classes.
import sys                              # For command-line argument handling.
import logging                          # To suppress Scapy warnings.

# Suppress Scapy runtime warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def help_text():
    """
    Display the correct usage of the script and exit.

    This function is called when the user does not provide the required command-line arguments.
    """
    print("\nUsage:\n python ipidscanner.py zombie_ip victim_ip victim_port\n")
    sys.exit()

def ipid_scanner(zombie_ip, victim_ip, victim_port):
    """
    Perform the idle scan using the provided zombie and victim details.

    Process:
        1. Sends a SYN-ACK packet to the zombie host and records its initial IPID.
        2. Sends a spoofed SYN packet to the victim, making it appear as if it originated from the zombie.
        3. Sends another SYN-ACK packet to the zombie host and records the final IPID.
    
    The difference between the initial and final IPID values indicates whether the victim's port is open or closed.
    
    Parameters:
        zombie_ip (str): The IP address of the zombie host.
        victim_ip (str): The IP address of the victim host.
        victim_port (str/int): The port number on the victim to scan.
    
    Returns:
        tuple: A tuple containing the initial and final IPID values from the zombie.
    """
    # Create a SYN-ACK packet to send to the zombie host on port 3322.
    synack_to_zombie = IP(dst=zombie_ip) / TCP(dport=3322, flags='SA')
    
    # Send the SYN-ACK packet to the zombie and capture its response.
    zombie_response = sr1(synack_to_zombie, verbose=0)
    print("\n[+] Sending SYN-ACK to zombie")
    
    # Record the initial IPID value from the zombie's response.
    initial_ipid = zombie_response.id
    print("\n[+] Recording initial IPID")
    
    # Create a spoofed SYN packet from the zombie to the victim.
    syn_to_victim = IP(src=zombie_ip, dst=victim_ip) / TCP(dport=int(victim_port), flags='S')
    
    # Send the spoofed SYN packet to the victim.
    send(syn_to_victim, verbose=0)
    print("\n[+] Sending spoofed SYN to victim")
    
    # Send another SYN-ACK to the zombie to get the updated IPID after the spoofed packet.
    zombie_response = sr1(synack_to_zombie, verbose=0)
    print("\n[+] Sending SYN-ACK to zombie")
    
    # Record the final IPID value from the zombie's response.
    final_ipid = zombie_response.id
    print("\n[+] Recording final IPID\n")
    
    print("[*] Initial IPID of zombie: {}\n[*] Final IPID of zombie: {}".format(initial_ipid, final_ipid))
    return initial_ipid, final_ipid

def check_port_status(initial_ipid, final_ipid, victim_ip, victim_port):
    """
    Determine the status of the victim's port based on the change in the zombie's IPID values.

    The logic is as follows:
        - If the initial IPID is one less than the final IPID, no extra packet was sent by the zombie,
          indicating that the victim's port is closed or filtered.
        - If the initial IPID is two less than the final IPID, it implies that an extra packet was sent,
          suggesting that the victim's port is open.
        - Any other difference suggests that the zombie's IPID sequence is not behaving as expected.
    
    Parameters:
        initial_ipid (int): The initial IPID value recorded from the zombie.
        final_ipid (int): The final IPID value recorded from the zombie.
        victim_ip (str): The victim's IP address.
        victim_port (str/int): The port on the victim being scanned.
    """
    # Analyze the difference between IPID values to infer the port status.
    if initial_ipid == final_ipid - 1:
        print("\n[*] The port {} on {} is closed | filtered\n".format(victim_port, victim_ip))
    elif initial_ipid == final_ipid - 2:
        print("\n[*] The port {} on {} is open\n".format(victim_port, victim_ip))
    else:
        print("\n[*] {} is a Bad zombie, try another!!\n".format(victim_ip))
    
if __name__ == '__main__':
    # Ensure the script is executed with the correct number of command-line arguments.
    if len(sys.argv) < 4:
        help_text()
    
    # Parse command-line arguments.
    zombie_ip = sys.argv[1]
    victim_ip = sys.argv[2]
    victim_port = sys.argv[3]
    
    # Perform the idle scan and record IPID values.
    initial_ipid, final_ipid = ipid_scanner(zombie_ip, victim_ip, victim_port)
    
    # Check and print the port status based on the IPID difference.
    check_port_status(initial_ipid, final_ipid, victim_ip, victim_port)
