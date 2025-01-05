# Ping and Traceroute

A Python script that executes a ping or a traceroute. 

Ping sends an ICMP packet type 8, echo request, to the desired host. After user exits the loop (esc key), program will display the min, max, and average round trip time, as well as any packet loss encountered.

Traceroute utilizes ping with an incrementally increasing TTL until it reaches the destination host. This implementation handles hop timeouts by automatically trying the next hop, allowing for a start-to-finish path where routers don't accommodate echo requests.

Program is based on skeleton code provided for CS 374 - Intro to Computer Networks at Oregon State University.

## Installation

- Requires Python3, virtual environment recommended if you're just checking it out.
- From the project folder, run "pip install -r requirements.txt"
  - This installs the Keyboard module, which has a lot of low-level dependencies.
  - You can also install this manually with "pip install keyboard"
  - More info: [https://pypi.org/project/keyboard/](https://pypi.org/project/keyboard/)


## Instructions
**Sending ICMP packets requires superuser access. Please launch script with sudo command.**
- run "sudo python3 trace_ping.py"
- Press 1 to use Traceroute or press 2 to use Ping
- Enter a valid hostname (optional subdomain, domain, and TLD; no URL scheme) or IP address
- If using Ping, the script will send an echo request once per second until you press escape.

## Output examples:
