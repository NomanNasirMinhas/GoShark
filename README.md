# GoShark

## About

GoLang based Wireless Network Analysis tool. This tool is designed to be a simple, easy to use, and fast wireless network analysis tool. It is designed to be used by network administrators, security professionals, and anyone else who needs to analyze wireless networks.

## Pre-Reqs

Make sure that libpcap is installed on your system as per your OS.

Run the software with Administrator/Root privileges.


## Live Development

To run in live development mode, run `wails dev` in the project directory. This will run a Vite development
server that will provide very fast hot reload of your frontend changes. If you want to develop in a browser
and have access to your Go methods, there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

## Building

To build a redistributable, production mode package, use `wails build`.

## Features (Planned)

- [x] Capture Traffic on different interfaces
- [x] Allow Easy Filtering
- [x] Export to PCAP
- [x] Add Suricata Rules
- [x] Add Snort Rules
- [x] Add Yara Rules
- [ ] IP Address Resultion
- [ ] Import PCAP
- [ ] Add File Detection
- [ ] Add File Extraction
- [ ] Add Base64 Detection
- [ ] Add DNS Tunnel Detection
- [ ] Add ARP Spoof Support
- [ ] Add Port Scanner
- [ ] Add TLS Proxy Support


