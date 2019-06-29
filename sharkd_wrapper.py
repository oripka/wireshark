#!/usr/bin/env python3
import json
import socket
import sys

HOST = '127.0.0.1'
PORT = 4446

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def sharkd_run_command(json_command):
    cmd = json.dumps(json_command)
    cmd_n = cmd+"\n"
    print("Sending: "+cmd)
    s.send(cmd_n.encode())


def send_receive(json_command):
    sharkd_run_command(json_command)
    while True:
        data = s.recv(1024).decode("utf-8")

        sys.stdout.write(data)
        print("Data length: "+str(len(data)))
        if "\n" in data:
            return


s.connect((HOST, PORT))

send_receive({"req": "status"})
# primitive to open file but do not dissect
#send_receive({"req": "load", "file": "test.pcap", "frames": "1 2 3 4 5 6 7"})

send_receive({"req": "load", "file": "test1.pcap"})
# dissect x packets
send_receive({"req": "frame", "frame": "6", "proto": True})

# return the dissected frame
# send_receive({"req": "status"})
