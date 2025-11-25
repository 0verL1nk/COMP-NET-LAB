# ICMP Ping Application

This is a simple ping application built on top of the network protocol stack.

## Building

```bash
make build
```

## Usage

```bash
sudo ./build/ping_app <target_ip>
```

Example:
```bash
sudo ./build/ping_app 192.168.1.1
```

## Features

- Sends 4 ICMP Echo requests at 1-second intervals
- Displays response time for each reply
- Shows statistics including packet loss and RTT (min/avg/max)
- Automatically handles timeouts (5-second timeout per request)

## Implementation Details

The ping application extends the existing ICMP module with:
- Request tracking using a map data structure
- Timestamp-based scheduling (non-blocking)
- Response time measurement
- Statistics collection and reporting

The implementation follows the same architectural patterns as the existing protocol stack components.