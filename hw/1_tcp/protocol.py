import socket


PACKET_SIZE = 508  # 576 - 60 - 8
HEADER_SIZE = 8
DATA_SIZE = PACKET_SIZE - HEADER_SIZE
SEND_WINDOW = 3
RECV_WINDOW = 5
RETRIES = 32
UDP_TIMEOUT = 0.0015


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, payload):
        return self.udp_socket.sendto(payload, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class Header:
    def __init__(self, seq: int, ack: int):
        self.seq = seq
        self.ack = ack

    def to_bytes(self):
        return self.seq.to_bytes(4, 'big') + self.ack.to_bytes(4, 'big')
    
    @staticmethod
    def from_bytes(bytes):
        return Header(int.from_bytes(bytes[:4], 'big'),  int.from_bytes(bytes[4:], 'big'))


class Packet:
    def __init__(self, data: bytes, seq: int, ack: int):
        self.header = Header(seq, ack)
        self.data = data

    def to_bytes(self):
        return self.header.to_bytes() + self.data

    @staticmethod
    def from_bytes(data: bytes):
        header = Header.from_bytes(data[:HEADER_SIZE])
        return Packet(data[HEADER_SIZE:], seq=header.seq, ack=header.ack)


class Segment:
    def __init__(self, data: bytes, left: int, right: int):
        self.data = data
        self.left = left
        self.right = right


class Batcher:
    
    def __init__(self, payload: bytes):
        self._payload = payload
    
    def iter(self, start=0):
        n = len(self._payload)
        cur = 0
        while cur < n:
            cur_packet = self._payload[cur:cur + DATA_SIZE]
            yield Segment(cur_packet, start + cur, start + min(len(self._payload), cur + DATA_SIZE))
            cur += DATA_SIZE

    def make_segments(self, start=0):
        self.pointer = 0
        self.segments = list(self.iter(start))

    def next_segment(self):
        self.pointer += 1
        return self.segments[self.pointer - 1]
 
    def has_segments(self):
        return self.pointer < len(self.segments)


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(UDP_TIMEOUT)
        self.ack = 1
        self.ack = 1
        self.recv_bytes = 1
        self.seq = 1

    def _send_ack(self, seq=0):
        self.sendto(Header(seq=seq, ack=self.ack).to_bytes())

    def send_segment(self, segment: Segment):
        tcp_packet = Packet(data=segment.data, seq=segment.left, ack=self.ack)
        self.sendto(payload=tcp_packet.to_bytes())

    def send_segments(self, segments):
        for segment in segments:
            self.send_segment(segment)

    def fill_segments(self, segments: list[Segment], batcher: Batcher):
        added = 0
        while len(segments) < SEND_WINDOW and batcher.has_segments():
            segments.append(batcher.next_segment())
            added += 1
        return added

    def update_segments(self, segments: list[Segment], batcher: Batcher, recv_packet: Packet):
        received_pkgs = (recv_packet.header.ack - self.ack + DATA_SIZE - 1) // DATA_SIZE
        segments = segments[received_pkgs:]
        self.fill_segments(segments, batcher)
        return segments

    def recv_tcp_packet(self) -> Packet:
        return Packet.from_bytes(self.recvfrom(PACKET_SIZE))

    def send(self, data: bytes):
        batcher = Batcher(data)
        batcher.make_segments(self.ack)
        segments = []
        self.fill_segments(segments, batcher)
        while segments:
            self.send_segments(segments)
            errors_cnt = 0
            for _ in range(RETRIES):
                try:
                    resp: Packet = self.recv_tcp_packet()
                except Exception as e:
                    errors_cnt += 1
                    self.send_segments(segments)
                    continue
                if resp.header.ack == self.ack:
                    break
                if resp.header.ack > self.ack:
                    segments = self.update_segments(segments, batcher, resp)
                    self.ack = resp.header.ack
            if errors_cnt == RETRIES:
                break
        return len(data)

    def try_receive(self):
        received: list[Packet] = []
        for _ in range(RECV_WINDOW):
            try:
                tcp_packet = self.recv_tcp_packet()
            except Exception:
                continue
            received.append(tcp_packet)
        received.sort(key=lambda tcp: tcp.header.seq)
        data = bytes()
        for packet in received:
            if packet.header.seq < self.ack:
                continue
            if packet.header.seq == self.ack:
                self.ack += len(packet.data)
                data += packet.data
            else:
                break
        return data

    def recv(self, n: int):
        current_bytes = self.ack
        data = bytes()
        while self.ack < current_bytes + n:
            data += self.try_receive()
            self._send_ack()
        return data
    
    def close(self):
        super().close()
