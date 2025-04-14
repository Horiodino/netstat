# GoMid - Network Traffic Monitor

GoMid is a real-time network traffic monitoring tool built in Go that provides packet-level visibility into process network communications.

## Features

- **Process-Based Monitoring**: Focus on network traffic from specific applications
- **Real-Time Packet Inspection**: View packets as they're captured with detailed information
- **Protocol Analysis**: Automatic detection and formatting of common protocols (HTTP, DNS)
- **Terminal User Interface**: Easy-to-use TUI built with Bubble Tea
- **Detailed Packet Information**: View headers, payload data, and hex dumps
- **Connection Tracking**: See active network connections for all processes

## Architecture

GoMid uses a client-server architecture:

- **Server**: Captures network packets using libpcap and monitors system processes
- **Client**: Provides a terminal user interface to view and analyze the captured data

## Requirements

- Go 1.24 or later
- Root/sudo privileges (required for packet capture)
- Linux operating system

## Dependencies

- [github.com/charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea) - Terminal UI framework
- [github.com/google/gopacket](https://github.com/google/gopacket) - Packet processing library
- [github.com/shirou/gopsutil](https://github.com/shirou/gopsutil) - Process and system information

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Horiodino/netstat.git
cd netstat
```

2. Build the application:

```bash
go build -o bin/gomid-server ./server
go build -o bin/gomid-client ./client
```

## Usage

1. First, start the server with root privileges:

```bash
sudo ./bin/gomid-server
```

2. Then, in another terminal, start the client:

```bash
./bin/gomid-client
```

3. The client will display a list of active network processes.
4. Use arrow keys to navigate and press Enter to monitor a specific process.
5. View real-time packet data with the following controls:
   - `d` - Toggle between summary and detailed view
   - `r` - Refresh capture
   - `q` - Return to process list or quit

## Logs

The application creates log files that can be useful for troubleshooting:

- `netmon-server.log` - Server logs
- `netmon-client.log` - Client logs

## How It Works

1. The server uses libpcap to capture network packets
2. It identifies which process each packet belongs to based on connection information
3. The client connects to the server via TCP
4. The server sends process information and packet data to the client
5. The client displays this information in a user-friendly interface