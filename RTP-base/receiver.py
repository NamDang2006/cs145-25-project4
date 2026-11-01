import argparse
import socket
import sys
from utils import PacketHeader, compute_checksum
PKT_START = 0
PKT_END = 1
PKT_DATA = 2
PKT_ACK = 3


def create_ack(seq_num):
    pkt_header = PacketHeader(
        type=PKT_ACK, seq_num=seq_num, length=0, checksum=0
    )
    pkt_header.checksum = compute_checksum(pkt_header / b"")
    return bytes(pkt_header / b"")


def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    connected = False
    client_addr = None
    expected_seq = 0
    buffer = {}

    while True:
        pkt, address = s.recvfrom(2048)
        if len(pkt) < 16:
            continue

        pkt_header = PacketHeader(pkt[:16])
        msg = pkt[16 : 16 + pkt_header.length]

        pkt_checksum = pkt_header.checksum
        pkt_header.checksum = 0
        computed_checksum = compute_checksum(pkt_header / msg)
        if pkt_checksum != computed_checksum:
            continue

        pkt_type = pkt_header.type
        seq_num = pkt_header.seq_num

        if not connected:
            if pkt_type == PKT_START:
                connected = True
                client_addr = address
                expected_seq = 0
                buffer.clear()
                s.sendto(create_ack(expected_seq), address)
            continue

        if address != client_addr:
            continue

        if pkt_type == PKT_START:
            if expected_seq == 0 and not buffer:
                s.sendto(create_ack(expected_seq), address)
            continue

        if pkt_type == PKT_DATA:
            if seq_num >= expected_seq + window_size:
                continue

            if seq_num >= expected_seq:
                buffer[seq_num] = msg

            while expected_seq in buffer:
                sys.stdout.buffer.write(buffer.pop(expected_seq))
                expected_seq += 1
            sys.stdout.buffer.flush()
            sys.stdout.flush()

            s.sendto(create_ack(expected_seq), address)

        elif pkt_type == PKT_END:
            if seq_num == expected_seq:
                s.sendto(create_ack(expected_seq + 1), address)
                sys.stdout.buffer.flush()
                sys.stdout.flush()
                break
            else:
                s.sendto(create_ack(expected_seq), address)

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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
