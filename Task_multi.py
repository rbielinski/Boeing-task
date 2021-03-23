#!/usr/bin/env python3
"""Boeing AvionX recruitment task.

Version with non-blocking sockets and a selector to handle multiple connections.
Server stays open until KeyboardInterrupt.
@author: Radoslaw Bielinski
"""

import argparse
import selectors
import socket
import types
import zlib


HOST = "127.0.0.1"


def pack_data(data):
    """Return data packed in frames as a bytearray."""
    i = 1
    packet = bytearray()
    for payload in data:
        idx = i.to_bytes(2, "big")
        enc_payload = payload.encode()
        payload_len = len(enc_payload).to_bytes(2, "big")
        crc32 = zlib.crc32(idx + payload_len + enc_payload).to_bytes(4, "big")

        packet += idx + payload_len + enc_payload + crc32
        i += 1
    return packet


def process_data(data):
    """Print payloads from data if corresponding checksums are correct."""
    while data:
        payload_len = int.from_bytes(data[2:4], byteorder="big")
        crc32 = zlib.crc32(data[: 4 + payload_len]).to_bytes(4, "big")
        if crc32 == data[4 + payload_len : 8 + payload_len]:
            payload = data[4 : 4 + payload_len].decode()
            print(payload)
        else:
            print("Crc32 not equal")
        data = data[8 + payload_len :]


# multi-connection non-blocking server with selector
def server(port):
    """Open server, receive data from clients and print if not corrupt."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
        sel = selectors.DefaultSelector()
        serversocket.bind((HOST, port))
        serversocket.listen()
        serversocket.setblocking(False)
        sel.register(serversocket, selectors.EVENT_READ, data=None)
        try:
            while True:
                events = sel.select(timeout=1)
                for key, mask in events:
                    if key.data is None:
                        # in this case key is associated with serversocket
                        conn, addr = key.fileobj.accept()
                        conn.setblocking(False)
                        data = types.SimpleNamespace(inb=b"")
                        sel.register(conn, selectors.EVENT_READ, data=data)
                    else:
                        # in this case key is associated with conn (the client)
                        data = key.data
                        packet_in = key.fileobj.recv(1024)
                        if packet_in:
                            data.inb += packet_in
                        else:
                            sel.unregister(key.fileobj)
                            key.fileobj.close()
                            process_data(data.inb)
        except KeyboardInterrupt:
            print("exiting due to caught keyboard interrupt")
        finally:
            sel.close()


def client(port, data):
    """Open client, send data to server and write it to 'sent.bin'."""
    packet_out = pack_data(data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientsocket:
        clientsocket.connect((HOST, port))
        clientsocket.sendall(packet_out)
    with open("sent.bin", "wb") as f:
        f.write(packet_out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--listen-port", type=int, help="listen port; enables server mode"
    )
    mode.add_argument(
        "--target-port", type=int, help="targeted port; enables client mode"
    )
    parser.add_argument(
        "--data",
        action="append",
        type=str,
        help="data to be sent; use only with --target-port",
    )
    args = parser.parse_args()

    if args.listen_port:
        if args.data:
            parser.error("--data can only be used along with --target-port")
        else:
            server(args.listen_port)
    elif args.target_port:
        if not args.data:
            parser.error("please provide data to be sent to server")
        else:
            client(args.target_port, args.data)
