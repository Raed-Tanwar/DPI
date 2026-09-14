# DPI Engine

A **Java-based offline Deep Packet Inspection (DPI) engine** for analyzing, classifying, and filtering network traffic from PCAP captures.

The engine parses Ethernet II/IPv4 packets, extracts hostnames from supported TLS ClientHello, HTTP, and DNS packets, and applies blocking rules based on **source IPv4 address**, **application classification**, or **domain**. Forwarded packets are written to an output PCAP file.

Both **single-threaded** and **multi-threaded** processing modes are available.

> **Scope:** This project processes capture files offline. It does not capture live traffic, enforce operating-system firewall rules, or decrypt HTTPS payloads.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Running the Engine](#running-the-engine)
- [Blocking Rules](#blocking-rules)
- [Output and Verification](#output-and-verification)
- [Testing](#testing)
- [Limitations and Known Issues](#limitations-and-known-issues)

---

## Features

- **Classic PCAP input** — Reads microsecond-resolution PCAP captures with automatic little-endian and big-endian handling.
- **PCAP output** — Writes forwarded packet data to an output capture.
- **Packet parsing** — Parses Ethernet II, IPv4, TCP, and UDP headers, including TCP flags.
- **TLS SNI extraction** — Extracts Server Name Indication from supported TLS ClientHello packets.
- **HTTP hostname extraction** — Extracts hostnames from supported HTTP `Host:` headers.
- **DNS query extraction** — Extracts queried domain names from supported DNS packets.
- **Heuristic application classification** — Identifies selected services through hostname patterns.
- **Sticky directional-flow filtering** — Retains a blocking decision for subsequent packets in the same tracked directional flow.
- **Multi-threaded processing** — Uses hash-based flow routing, worker-local connection tables, blocking queues, atomic statistics, and synchronized output writes.
- **CLI validation** — Reports unsupported options, unknown application names, invalid IPv4 rules, and nonnumeric thread arguments.
- **Processing reports** — Displays forwarding/drop counts and detected domains. Multi-threaded mode also reports worker activity and application statistics.

---

## How It Works

1. Read a packet from the input PCAP.
2. Parse its Ethernet and IPv4 headers, followed by TCP or UDP headers where applicable.
3. Identify its directional flow using a five-tuple:

   ```text
   source IP, destination IP, source port, destination port, protocol
   ```

4. Attempt hostname or domain extraction based on the destination port:

   | Destination port | Extraction attempted |
   |---|---|
   | `443` | TLS ClientHello SNI |
   | `80` | HTTP `Host:` header |
   | `53` | DNS query domain |

5. Classify the flow using extracted hostnames or port-based fallbacks.
6. Evaluate blocking rules.
7. Write forwarded packets to the output PCAP.

### Multi-threaded architecture

```text
PCAP reader and parser
          |
          v
      Input queue
          |
          v
 Hash-based load balancer
          |
    +-----+-----+
    |     |     |
    v     v     v
 Worker Worker Worker
    |     |     |
 Worker-local flow tables
    |     |     |
    +-----+-----+
          |
          v
 Shared synchronized PCAP writer
```

Packets with the same directional five-tuple are routed to the same worker. Reverse-direction traffic is treated as a separate flow.

---

## Project Structure

```text
src/
├── main/java/com/dpi/
│   ├── engine/
│   │   ├── DPIEngine.java              # Single-threaded engine
│   │   ├── MultiThreadedDPIEngine.java # Multi-threaded engine
│   │   ├── LoadBalancerThread.java     # Hash-based worker routing
│   │   ├── FastPathThread.java         # Packet-processing worker
│   │   ├── ConnectionTracker.java      # Worker-local flow tracking and eviction
│   │   ├── PacketJob.java              # Queued packet wrapper
│   │   └── RuleManager.java            # Blocking-rule management
│   ├── parser/
│   │   ├── PacketParser.java           # Ethernet, IPv4, TCP, and UDP parsing
│   │   └── ParsedPacket.java           # Parsed packet fields
│   ├── extractor/
│   │   ├── SNIExtractor.java           # TLS ClientHello SNI extraction
│   │   ├── HTTPHostExtractor.java      # HTTP Host extraction
│   │   └── DNSExtractor.java           # DNS query extraction
│   ├── pcap/
│   │   ├── PcapReader.java             # Classic PCAP reader
│   │   ├── PcapWriter.java             # PCAP output writer
│   │   └── RawPacket.java              # Raw packet data and metadata
│   └── types/
│       ├── FiveTuple.java              # Directional flow identifier
│       ├── IpUtil.java                 # IPv4 address conversion
│       ├── Connection.java             # Tracked connection data
│       ├── ConnectionState.java        # Connection-state enum
│       ├── AppType.java                # Application labels and hostname matching
│       ├── PacketAction.java           # FORWARD / DROP
│       └── DPIStats.java               # Atomic statistics counters
└── test/java/com/dpi/test/
    └── DpiEngineTest.java              # JUnit tests

pom.xml                                # Maven configuration, version 2.0.0
build.sh / build.bat                    # Compilation helpers
run.sh / run.bat                        # Java launch helpers
test_dpi.pcap                          # Included sample capture
generate_test_pcap.py                   # Sample capture generator
verify_pcap.py                         # Basic PCAP information utility
verify_all.py                          # Command-line verification script
```

---

## Prerequisites

- **JDK 11 or newer** — Required for compilation and execution.
- **A supported PCAP capture** — The repository includes `test_dpi.pcap`.
- **Maven** — Optional; required for Maven builds and JUnit test execution.
- **Python 3** — Optional; required for the included Python utilities.
- **Wireshark** — Optional; useful for inspecting output captures.

Use classic microsecond-resolution PCAP captures containing Ethernet II/IPv4 traffic. See [Limitations and Known Issues](#limitations-and-known-issues) for unsupported formats and processing constraints.

---

## Build Instructions

### Clone the repository

```bash
git clone https://github.com/Raed-Tanwar/DPI.git
cd DPI
```

### Linux / macOS

```bash
bash build.sh
```

Alternatively, make the scripts executable:

```bash
chmod +x build.sh run.sh
./build.sh
```

### Windows PowerShell

```powershell
.\build.bat
```

### Windows CMD

```cmd
build.bat
```

### Manual compilation

Run this command from the repository root:

```bash
javac -encoding UTF-8 -d bin src/main/java/com/dpi/types/*.java src/main/java/com/dpi/pcap/*.java src/main/java/com/dpi/parser/*.java src/main/java/com/dpi/extractor/*.java src/main/java/com/dpi/engine/*.java
```

The helper scripts and manual command place compiled classes in `bin`.

### Maven build

```bash
mvn package
```

Maven places compiled classes in `target/classes` and creates:

```text
target/packet-analyzer-2.0.0.jar
```

> The `-cp bin` examples below assume you used the helper scripts or manual compilation. For a Maven build, use `-cp target/classes` instead, or launch the generated JAR as shown below.

---

## Running the Engine

Run commands from the repository root.

### Single-threaded usage

Without blocking rules:

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out_single.pcap
```

With blocking rules:

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap out_single.pcap --block-app YouTube --block-ip 192.168.1.50
```

### Multi-threaded usage

Using four worker threads:

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_multi.pcap --threads 4
```

With blocking rules:

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_multi.pcap --threads 4 --block-app YouTube --block-ip 192.168.1.50
```

When `--threads` is omitted, the default worker count is based on the processors available to the JVM.

### Using the shell launcher

The launcher expects the fully qualified main class:

```bash
bash run.sh com.dpi.engine.DPIEngine test_dpi.pcap out_single.pcap
```

```bash
bash run.sh com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_multi.pcap --threads 4
```

### Running the Maven-built JAR

Single-threaded:

```bash
java -Dfile.encoding=UTF-8 -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap out_single.pcap
```

Multi-threaded:

```bash
java -Dfile.encoding=UTF-8 -cp target/packet-analyzer-2.0.0.jar com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap out_multi.pcap --threads 4
```

### CLI options

| Option | Available in | Description |
|---|---|---|
| `--block-ip IP` | Both engines | Block a source IPv4 address |
| `--block-app APP` | Both engines | Block an application classification |
| `--block-domain TEXT` | Both engines | Block extracted hostnames/domains containing the supplied text |
| `--threads N` | Multi-threaded | Set the worker count |
| `--lbs N` | Multi-threaded | Used with positive `--fps` to calculate worker count |
| `--fps M` | Multi-threaded | When positive, sets worker count to `lbs × fps`, overriding `--threads` |

**Note:** The current implementation creates one load-balancer thread. `--lbs` does not create additional load balancers. Prefer `--threads` for straightforward worker configuration.

---

## Blocking Rules

Rules can be combined and repeated. A match against **any** configured rule causes blocking.

### Block a source IPv4 address

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap filtered.pcap --block-ip 192.168.1.50
```

This checks the packet’s **source address only**.

It does not match destination addresses, CIDR ranges, or IPv6 addresses.

### Block an application

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap filtered.pcap --block-app YouTube
```

Application rule names are case-insensitive. For example, `YouTube` and `YOUTUBE` are equivalent.

Hostname-based service labels include:

```text
YOUTUBE, FACEBOOK, GOOGLE, NETFLIX, AMAZON, MICROSOFT,
APPLE, INSTAGRAM, TWITTER, TELEGRAM, TIKTOK, SPOTIFY,
ZOOM, DISCORD, GITHUB, CLOUDFLARE, WHATSAPP
```

The enum also accepts:

```text
UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC
```

`HTTP`, `HTTPS`, and `DNS` are used by port-based fallback classification. The presence of `TLS` and `QUIC` enum values does not imply dedicated detection support for those labels.

Service detection uses hostname substring heuristics and is not an exhaustive application signature database.

### Block a domain or hostname substring

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap filtered.pcap --block-domain youtube.com
```

Domain rules use **case-insensitive substring matching** against the extracted TLS SNI, HTTP hostname, or DNS query domain.

For example, `--block-domain example.com` matches:

```text
example.com
www.example.com
notexample.com
```

It is not exact-domain matching or domain-boundary-aware suffix matching.

### Combine multiple rules

```bash
java -Dfile.encoding=UTF-8 -cp bin com.dpi.engine.DPIEngine test_dpi.pcap filtered.pcap --block-app YouTube --block-app Facebook --block-domain example.com --block-ip 192.168.1.50
```

### Sticky blocking behavior

Once a flow matches a rule:

- The matching packet is dropped.
- Subsequent packets in the same directional five-tuple remain blocked while that flow’s state is retained.
- Packets already forwarded before classification remain in the output.
- Reverse-direction packets belong to a separate flow and do not automatically inherit the block.

Multi-threaded workers use capacity-limited connection tables. Eviction can remove a flow’s classification and blocking state.

---

## Output and Verification

### Output capture

Packets receiving a `FORWARD` decision are written to the specified output file.

Non-IPv4 traffic is skipped by the current processing pipeline. Therefore, running without blocking rules does **not** guarantee a complete copy of the input capture.

Use different input and output paths; output files are overwritten.

### Console reports

Single-threaded mode reports:

- Total packets and bytes
- TCP and UDP packet counts
- Forwarded and dropped packets
- Detected domains and application labels

Multi-threaded mode reports:

- Total, forwarded, and dropped packets
- Active tracked flows
- Load-balancer dispatch count
- Per-worker processing counts
- Application breakdown
- Detected domains and application labels

Skipped packets can make the total packet count differ from the sum of forwarded and dropped packets.

### Inspect basic PCAP information

```bash
python verify_pcap.py out_single.pcap out_multi.pcap
```

This utility prints:

- PCAP magic number and version
- Snapshot length and link type
- Record count
- Total file size

It does **not** compare packet contents, establish byte equality, or comprehensively validate filtering behavior.

You can also open output captures in Wireshark.

### Comparing processing modes

**Multi-threaded output is not guaranteed to preserve global input order or match single-threaded output byte-for-byte.**

Workers write packets as they finish processing. Synchronized writes prevent overlapping output operations but do not restore the original ordering across workers.

The current multi-threaded implementation also has a shared packet-header issue described below.

---

## Testing

### JUnit tests

Run the repository’s JUnit tests with Maven:

```bash
mvn test
```

### Command-line verification script

After compiling to `bin`, run:

```bash
python verify_all.py
```

This script exercises several engine configurations and blocking-rule cases, and prints diagnostic results.

### Generate a sample capture

The repository includes a capture-generation utility:

```bash
python generate_test_pcap.py
```

The included `test_dpi.pcap` can also be used directly for the usage examples.

---

## Limitations and Known Issues

### Supported capture formats

- Supports classic **microsecond-resolution PCAP** in either byte order.
- Does not support **PCAPNG** or **nanosecond-resolution PCAP**.
- The parser assumes Ethernet framing.
- IPv6 inspection and VLAN-tag parsing are not implemented.

### Classification limits

- Hostname/domain extraction is attempted on destination ports `443`, `80`, and `53`.
- No TCP stream reassembly or IP fragment reassembly is implemented.
- TLS handshakes and HTTP headers split across packets may not be detected.
- HTTPS payloads are not decrypted.
- Encrypted ClientHello and QUIC application inspection are not implemented.
- Hostname substring heuristics can produce false positives or miss services using unrecognized domains.
- DNS queries are classified as `DNS`; their queried hostnames are not used to assign service labels such as `YOUTUBE`.

### Flow-tracking limits

- Flows are directional rather than bidirectional.
- Blocking does not retrospectively remove packets forwarded before classification.
- Worker connection-table eviction can discard sticky state.
- The single-threaded and multi-threaded engines have different flow-retention behavior, so equivalent decisions should not be assumed for every capture.

### Multi-threaded packet metadata

The reader currently assigns the same mutable packet-header object to queued packet clones:

```java
cloned.header = rawPacket.header;
```

Because the reader updates that object while workers process earlier packets, output timestamps may be incorrect or nondeterministic.

This requires a code fix that copies packet-header fields into an independent object for each queued packet.

### Output metadata

The writer stores packet-data length as both captured length and original length. For captures containing truncated packets, the original on-wire length is therefore not preserved.

---

**Built to explore deep packet inspection, application classification, and rule-based traffic filtering through offline PCAP analysis.**
