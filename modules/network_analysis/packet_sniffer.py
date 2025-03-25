from scapy.all import sniff
import json

def packet_callback(packet):
    """ Callback function to process each packet. """
    try:
        packet_info = {
            "src": packet.src if hasattr(packet, "src") else None,
            "dst": packet.dst if hasattr(packet, "dst") else None,
            "protocol": packet.proto if hasattr(packet, "proto") else "Unknown",
            "payload": str(packet.payload) if packet.payload else "No Payload"
        }
        with open("network_logs.json", "a") as log_file:
            json.dump(packet_info, log_file)
            log_file.write("\n")
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface="eth0", count=100):
    """ Starts packet sniffing on the given interface. """
    print(f"Starting packet capture on {interface}")
    sniff(iface=interface, prn=packet_callback, count=count)

if __name__ == "__main__":
    start_sniffing()
