# Ping and Traceroute

Python script that executes a ping or a traceroute. Ping sends an ICMP packet type 8, echo request, to the desired host. 

Traceroute utilizes ping with an incrementally increasing TTL until it reaches the destination host. This implementation handles hop timeouts by automatically trying the next hop, allowing for a start-to-finish path where routers don't accommodate echo requests.

Program is based on skeleton code provided for CS 374 - Intro to Computer Networks at Oregon State University.