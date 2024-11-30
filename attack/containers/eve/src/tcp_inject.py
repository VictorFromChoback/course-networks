from scapy.all import IP, Raw, TCP
import netfilterqueue


def inject(packet: IP, payload: str):
    packet[Raw].load = payload
    packet[IP].len = None
    packet[IP].chksum = None
    packet[TCP].chksum = None


def process(packet):
    ip_packet = IP(packet.get_payload())
    if ip_packet.haslayer(Raw):
        load: str = ip_packet[Raw].load.decode()
        if "public" in load:
            load = load.replace("public", "secret")
            inject(ip_packet, load)
            packet.set_payload(bytes(ip_packet))
            print("INFO: TCP INJECTED!")
    packet.accept()


def main():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process)
    queue.run()

if __name__ == "__main__":
    main()
