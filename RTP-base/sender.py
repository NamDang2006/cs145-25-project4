import argparse
import socket
import sys
import time
from utils import PacketHeader, compute_checksum
PKT_START = 0
PKT_END = 1
PKT_DATA = 2
PKT_ACK = 3

MAX_PAYLOAD_SIZE = 1472 - 16
TIMEOUT = 0.5
def create_packet(pkt_type, seq_num, data=b""):
    pkt_header = PacketHeader(
        type=pkt_type, seq_num=seq_num, length=len(data), checksum=0
    )
    pkt_header.checksum = compute_checksum(pkt_header / data)
    return bytes(pkt_header / data)
def verify_ack(raw_pkt):
    if len(raw_pkt) < 16:
        return None
    pkt_header = PacketHeader(raw_pkt[:16])
    payload = raw_pkt[16 : 16 + pkt_header.length]

    saved_checksum = pkt_header.checksum
    pkt_header.checksum = 0
    if compute_checksum(pkt_header / payload) != saved_checksum:
        return None

    if pkt_header.type != PKT_ACK:
        return None

    return pkt_header.seq_num
def sender(receiver_ip, receiver_port, window_size):
    """TODO: Open socket and send message from sys.stdin."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (receiver_ip, receiver_port)
    raw_data = sys.stdin.buffer.read()
    chunks = [
        raw_data[i : i + MAX_PAYLOAD_SIZE]
        for i in range(0, len(raw_data), MAX_PAYLOAD_SIZE)
    ]
    num_data_pkts = len(chunks)

    start_pkt = create_packet(PKT_START, seq_num=0)
    s.settimeout(TIMEOUT)
    while True:
        s.sendto(start_pkt, addr)
        try:
            raw_pkt, _ = s.recvfrom(2048)
            ack_seq = verify_ack(raw_pkt)
            if ack_seq is not None:
                break
        except socket.timeout:
            continue

    data_packets = [
        create_packet(PKT_DATA, seq_num=i, data=chunks[i])
        for i in range(num_data_pkts)
    ]

    base = 0
    next_seq = 0
    timer_start = None

    while base < num_data_pkts:
        while next_seq < min(base + window_size, num_data_pkts):
            s.sendto(data_packets[next_seq], addr)
            if timer_start is None:
                timer_start = time.time()
            next_seq += 1

        elapsed = time.time() - timer_start
        remaining = TIMEOUT - elapsed

        if remaining <= 0:
            for i in range(base, next_seq):
                s.sendto(data_packets[i], addr)
            timer_start = time.time()
            continue

        s.settimeout(remaining)
        try:
            raw_pkt, _ = s.recvfrom(2048)
            ack_seq = verify_ack(raw_pkt)

            if ack_seq is not None and ack_seq > base:
                base = ack_seq
                timer_start = time.time()
        except socket.timeout:
            for i in range(base, next_seq):
                s.sendto(data_packets[i], addr)
            timer_start = time.time()

    end_seq = num_data_pkts
    end_pkt = create_packet(PKT_END, seq_num=end_seq)
    s.sendto(end_pkt, addr)
    end_timer = time.time()

    while True:
        elapsed = time.time() - end_timer
        remaining = TIMEOUT - elapsed
        if remaining <= 0:
            break

        s.settimeout(remaining)
        try:
            raw_pkt, _ = s.recvfrom(2048)
            ack_seq = verify_ack(raw_pkt)
            if ack_seq is not None and ack_seq >= end_seq:
                break
        except socket.timeout:
            break

    s.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
