# Nuzzle
Nuzzle is a lightweight, fast packet sniffer that looks for unexpected network scans and potential attacks. It is intended for use by people who run online servers. (Regular home users probably won't have a use for it.)

Use Nuzzle to:
* Monitor: Learn about the scans and attacks your server typically receives.
* Detect: As part of an intrusion detection system (IDS), Nuzzle rapidly provides insight into the types of scans and attacks your system receives.
* Prevent: With Fail2Ban, implement a simple but extremely effective intrusion prevention system (IPS).

For more details and examples, including how to compile, install, run, and deploy as an IDS or IPS, see: https://nuzzle.hackerfactor.com/

## To compile and install
Use gcc or g++. (Should work on version 4.8 or later.)
* gcc -Wall -o nuzzle nuzzle.c
* g++ -Wall -o nuzzle nuzzle.c

Then use:
* sudo install nuzzle /usr/local/bin/

Run without any parameters (or use -h or -?) to see the usage.
Since it's a packet sniffer, it needs permission to access the network interface. The easiest way to do this is with:
* sudo nuzzle -i [interface] [other options]
