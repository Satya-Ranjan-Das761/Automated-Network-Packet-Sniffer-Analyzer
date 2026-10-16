
# Automated Network Packet Sniffer & Analyzer

## Overview
A Python cybersecurity project that captures network packet
metadata, identifies common protocols, analyzes traffic, and
generates CSV reports.

## Features
- Live packet capture
- TCP and UDP identification
- DNS, ICMP, and ARP recognition
- Source and destination address analysis
- Packet size and timestamp recording
- Protocol statistics
- CSV report generation

## Technologies
- Python 3
- Scapy
- Socket and network protocols
- CSV reporting

## Installation

Install Python 3 and Npcap on Windows.

Create a virtual environment:

    python -m venv .venv

Activate it in PowerShell:

    .\.venv\Scripts\Activate.ps1

Install the requirements:

    pip install -r requirements.txt

## Usage

Run a capture with a limit of 100 packets and 30 seconds:

    python packet_sniffer_analyzer.py --count 100 --timeout 30

To select a network interface:

    python packet_sniffer_analyzer.py --iface "INTERFACE_NAME" --count 100 --timeout 30

Replace INTERFACE_NAME with an available interface name.

## Output
The reports folder contains:
- Packet metadata CSV
- Protocol summary CSV
- Source address summary CSV

## Privacy and Responsible Use
The program records packet metadata, not packet payloads.
Capture traffic only on your own device or an authorized
network. Do not collect or share private traffic without permission.
