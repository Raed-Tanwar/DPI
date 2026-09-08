# DPI Engine 

A **Deep Packet Inspection (DPI) Engine** written in Java for analyzing, classifying, and filtering network traffic. It reads PCAP files, identifies application protocols (YouTube, Facebook, DNS, etc.), applies sticky flow-level blocking rules (by IP, application, or domain), and writes filtered PCAP files containing forwarded traffic.

---

## Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Build Instructions](#build-instructions)
5. [Running the Engine](#running-the-engine)
6. [Single-Threaded Usage](#single-threaded-usage)
7. [Multi-Threaded Usage](#multi-threaded-usage)
8. [Blocking Rules](#blocking-rules)
9. [Output](#output)

---

## Features

✅ **PCAP File Processing** - Read and parse network packets from PCAP files with automatic byte-order handling  
✅ **PCAP Output Writing** - Export forwarded packets to a valid `.pcap` file openable in Wireshark  
✅ **Protocol Detection** - Identify Ethernet II, IPv4, TCP (SYN, ACK, FIN, RST flags), UDP  
✅ **Application Classification** - Detect YouTube, Facebook, Google, Netflix, Twitter, Discord, Spotify, etc.  
✅ **SNI Extraction** - Extract Server Name Indication from TLS ClientHello handshakes  
✅ **Domain Detection** - Extract domains from HTTP `Host:` headers and DNS queries  
✅ **Sticky Flow-Level Filtering** - Block traffic by IP, application, or domain across entire connection flows  
✅ **Thread-Safe Architecture** - Deterministic hash-based worker routing and per-worker flow tables to prevent data races  
✅ **CLI Input Validation** - Gracefully report invalid rules or unsupported options  

---

## Project Structure

```
src/main/java/com/dpi/
├── engine/
│   ├── DPIEngine.java              # Single-threaded processing engine
│   ├── MultiThreadedDPIEngine.java # Multi-threaded processing engine
│   ├── LoadBalancerThread.java     # Hash-based load balancer (flow affinity)
│   ├── FastPathThread.java         # Worker thread with per-worker flow table
│   ├── ConnectionTracker.java      # Per-worker connection state and cleanup
│   ├── PacketJob.java              # Queued packet job wrapper
│   └── RuleManager.java            # Rule management for blocking
├── parser/
│   ├── PacketParser.java        # Packet parsing (Ethernet, IPv4, TCP, UDP)
│   └── ParsedPacket.java        # Parsed packet data structure
├── extractor/
│   ├── SNIExtractor.java        # Extract SNI from TLS ClientHello
│   ├── HTTPHostExtractor.java   # Extract Host header from HTTP
│   └── DNSExtractor.java        # Extract domain from DNS queries
├── pcap/
│   ├── PcapReader.java          # Read PCAP files
│   ├── PcapWriter.java          # Write filtered PCAP files
│   └── RawPacket.java           # Raw packet data structure
└── types/
    ├── FiveTuple.java           # Flow identifier (srcIP, dstIP, srcPort, dstPort, proto)
    ├── IpUtil.java              # Standard Big-Endian IP string/long converter
    ├── Connection.java          # Connection state tracking
    ├── ConnectionState.java     # Connection state enum (NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED)
    ├── AppType.java             # Application type enum
    ├── PacketAction.java        # Action enum (FORWARD/DROP)
    └── DPIStats.java            # Statistics tracking (AtomicLong)

pom.xml                          # Maven configuration (v2.0.0)
build.sh / build.bat             # Build helper scripts
run.sh / run.bat                 # Run helper scripts
```

---

## Prerequisites

- **Java 11+** (tested with JDK 21)
- **PCAP file** (e.g. `test_dpi.pcap`)

---

## Build Instructions

Compilation requires UTF-8 encoding flag:

### Linux / macOS:
```bash
./build.sh
```

### Windows (PowerShell / CMD):
```cmd
build.bat
```

Or manually:
```cmd
javac -encoding UTF-8 -d bin src/main/java/com/dpi/types/*.java src/main/java/com/dpi/pcap/*.java src/main/java/com/dpi/parser/*.java src/main/java/com/dpi/extractor/*.java src/main/java/com/dpi/engine/*.java
```

---

## Running the Engine

### Single-Threaded:
```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out1.pcap --block-app YouTube --block-ip 192.168.1.50
```

### Multi-Threaded:
```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out2.pcap --threads 4 --block-app YouTube --block-ip 192.168.1.50
```

---

## Output Verification

Both single-threaded and multi-threaded engines generate deterministic, byte-identical output PCAP files containing only `FORWARD` packets. Output files can be inspected using Wireshark or Python:

```bash
python verify_pcap.py out1.pcap out2.pcap
```
