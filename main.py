from scapy.all import ARP, Ether, srp, conf, get_if_addr, get_if_hwaddr

def scan_network(ip_range):
    # Create ARP request packet
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast frame
    packet = ether / arp_request

    # Send the packet and receive responses
    answered, _ = srp(packet, timeout=2, verbose=False)

    # Parse and display results
    devices = []
    for sent, received in answered:
        devices.append({"IP": received.psrc, "MAC": received.hwsrc})

    return devices

#Obtener IP/MASK
print(get_if_addr(conf.iface))
print(get_if_hwaddr(conf.iface))
print(conf.route.route("0.0.0.0"))
print(conf.route)

# Replace with your network's IP range (e.g., "192.168.1.1/24")
network_range = "192.168.1.1/24"
devices = scan_network(network_range)

# Print results
print("Connected devices:")
for device in devices:
    print(f"IP: {device['IP']}, MAC: {device['MAC']}")
    