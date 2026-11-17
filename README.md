# OpenFIR (`openfir`)

**OpenFIR** (**Open** **F**ast **I**nterleaved **R**eliable Transport Protocol) is a high-performance, multi-path, delay-gradient controlled, algebraically self-healing UDP file and directory transfer engine written in pure Go with zero external dependencies.

Engineered for high Bandwidth-Delay Product (BDP) wide-area networks, transcontinental links, satellite backhauls, and lossy wireless channels, OpenFIR decouples congestion control from random packet loss while eliminating retransmission round-trip penalties through coprime-stride erasure interleaving, in-flight content-addressed zero-byte teleportation, zero-RTT virtual continuous directory extents, and multi-socket 5-tuple striping.

---

## Core Architectural Innovations

### 1. $\phi$-Parity Coprime-Stride Interleaving & Belief-Propagation Peeling Decoder
Conventional Forward Error Correction (FEC) schemes group contiguous packets into block parity equations, which fail when network links experience Gilbert-Elliott contiguous burst losses.
* **Coprime Stride Interleaving:** OpenFIR weaves GF(2) algebraic parity equations (`PKT_PHI_PARITY`) across non-adjacent chunks separated by a coprime stride $S$ within a sliding window $W$. Any contiguous burst loss of up to $S$ packets impacts at most **one** symbol per algebraic equation.
* **Real-Time Peeling Decoder:** The receiver maintains an in-memory bipartite graph of pending parity equations backed by an L1 chunk ring cache. When an incoming data chunk or parity frame reduces an equation's unknown degree to $1$, the receiver immediately reconstructs the missing chunk via $O(1)$ XOR elimination and triggers a breadth-first cascade across dependent equations—healing lost packets locally without waiting for a NACK Round-Trip Time (RTT).

### 2. In-Flight Content-Addressed Zero-Byte Teleportation (`PKT_TELEPORT`)
Real-world datasets—such as virtual machine images, container layers, source trees, database snapshots, and uncompressed archives—contain substantial cross-region and cross-file block redundancy.
* **Zero-Payload Cloning:** The sender computes cryptographic SHA-256 digests for outgoing chunks on the fly. When a chunk matches any previously transmitted chunk across the entire transfer session, the sender suppresses the 1200-byte payload and transmits a compact **19-byte `PKT_TELEPORT` instruction**.
* **Reordering-Resilient Local Materialization:** Upon receiving `PKT_TELEPORT(TargetIdx <- SourceIdx)`, the receiver clones the payload directly from its in-memory L1 chunk cache or local storage via `pread`/`pwrite`. If `PKT_TELEPORT` arrives ahead of `SourceIdx` due to UDP reordering, the instruction is queued in a dependency map and automatically materialized the instant `SourceIdx` is committed.
* **Deadlock-Free NACK Fallback:** Any chunk requested via an explicit receiver NACK is strictly retransmitted as a raw `PKT_DATA` frame, guaranteeing 100% forward progress under arbitrary packet loss.

### 3. Zero-RTT Virtual Continuous Extent for Massive Small Files (`VirtualDirectoryExtent`)
Transferring tens of thousands of small files individually over high-RTT links suffers from catastrophic per-file handshake latency and filesystem `fsync` storms.
* **Tarless Zero-Temp-Disk Streaming:** When `-file` points to a directory, OpenFIR maps the entire directory tree in memory onto a **single deterministic Virtual Continuous Byte Extent** without writing any temporary archive to the sender's disk.
* **O(log N) Random-Access Retransmission:** File boundaries are indexed in an interval array. Arbitrary chunk reads and out-of-order NACK retransmissions resolve the underlying small file slices in $O(\log N)$ time via binary search.
* **Micro-File Coalescing & Cross-File Deduplication:** Multiple tiny files are automatically coalesced into single 1200-byte UDP frames, while $\phi$-Parity equations and `PKT_TELEPORT` deduplication operate seamlessly across file boundaries.

### 4. Kalman-Filtered One-Way Delay Gradient (KF-OWDG) Congestion Control
Instead of reducing transmission rates upon random packet loss or relying on two-way RTT measurements (which suffer from reverse-path ACK congestion), OpenFIR tracks the one-way arrival-versus-departure timestamp derivative:

$$\Delta d_k = (T_{\text{recv},k} - T_{\text{recv},k-1}) - (T_{\text{send},k} - T_{\text{send},k-1})$$

* **Clock-Offset Cancellation:** Constant clock offsets between sender and receiver cancel out algebraically without requiring NTP synchronization.
* **1D Kalman Noise Filtering:** A scalar Kalman filter separates OS scheduling jitter from true bottleneck queue buildup, driving a microsecond-resolution token-bucket pacer that keeps bottleneck router queues shallow while fully saturating available link capacity.

### 5. Multi-Path UDP Socket Striping & Multi-Core AEAD Pipeline
* **Concurrent Source-Port Striping:** The OpenFIR client opens a configurable pool of $N$ independent local UDP sockets (default `8`) and stripes outgoing datagrams round-robin across all $N$ 5-tuples, keeping per-flow rates below carrier anti-DDoS policing thresholds.
* **Multi-Path Feedback Survivability:** The receiver dynamically tracks all active client endpoints per session and rotates `PKT_FEEDBACK` frames across all observed paths.
* **`OFIRv1` AAD-Bound `AES-256-GCM` Security:** Every datagram begins with a 6-byte printable ASCII protocol header (`OFIRv1`) bound as Additional Authenticated Data (AAD), followed by a bijectively whitened 96-bit nonce and an `AES-256-GCM` encrypted payload processed across a multi-core worker pool.

---

## System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                  OpenFIR SENDER                                   |
|                                                                                   |
|  [Single File OR Directory Tree] --> [Virtual Continuous Extent (O(log N) Index)] |
|                                                    |                              |
|                                                    v                              |
|                                    [SHA-256 Content-Addressable Index]            |
|                                         /                     \                   |
|                              (New Hash)/                       \(Seen Hash)       |
|                                       v                         v                 |
|  [Phi-Stride Interleaver] <----- [PKT_DATA]              [PKT_TELEPORT]           |
|             |                         \                         /                 |
|             v                          v                       v                  |
|     [PKT_PHI_PARITY] -------------> [Micro-Burst Token-Bucket Pacer]              |
|                                                |            ^                     |
|                                                v            | (Kalman OWDG)       |
|                               [OFIRv1 AAD + AES-256-GCM Sealer]                   |
|                                                |                                  |
|                                                v                                  |
|                            [Multi-Path UDP Socket Striping Pool (1..N)]           |
+------------------------------------------------|------------+---------------------+
                                                 |            |
                            Multi-5-Tuple UDP    |            | PKT_FEEDBACK
                          (High-BDP / Lossy WAN) v            | (Rotated Paths)
+------------------------------------------------|------------+---------------------+
|                                 OpenFIR RECEIVER            |                     |
|                                                             |                     |
|                            [Multi-Core AES-256-GCM Worker Pool]                   |
|                                     /          |             \                    |
|                      (PKT_PHI_PARITY)      (PKT_DATA)   (PKT_TELEPORT)            |
|                            /                   |                 \                |
|                           v                    v                  v               |
|            [Peeling Decoder Graph] ===> [Commit + L1 Cache] <=== [Teleport Queue] |
|                                                |                                  |
|                                                v                                  |
|                         [Out-of-Order pwrite + SHA-256 + Dir Unpacker]            |
+-----------------------------------------------------------------------------------+
```

---

## Wire Frame Specification

All frames are encapsulated inside an authenticated outer AEAD envelope (34 bytes total overhead):

```text
+-----------------------+--------------------------+--------------------------------+
|  ASCII Header (6B)    |   Whitened Nonce (12B)   |  AES-256-GCM Ciphertext + Tag  |
|      "OFIRv1"         |  Bijective SplitMix96    |  (Inner Frame + 16B GMAC Tag)  |
+-----------------------+--------------------------+--------------------------------+
|<--- GCM AAD Bound --->|
```

Once decrypted and authenticated via `AES-256-GCM`, the inner plaintext frame begins with a 3-byte header (`[0x4F, 0x46, FrameType]`):

| `FrameType` | Name | Inner Payload Layout | Description |
| :--- | :--- | :--- | :--- |
| `0x01` | `PKT_HANDSHAKE` | `[8B TxID][8B Size][4B ChunkSz][4B Chunks][32B SHA256][1B Flags][2B NameLen][Name]` | Session initialization (`Flags=0x01` indicates directory bundle) |
| `0x02` | `PKT_HANDSHAKE_ACK` | `[8B TxID][4B HighestContiguous]` | Idempotent session readiness confirmation |
| `0x03` | `PKT_DATA` | `[4B ChunkIdx][8B SendTimestampNano][2B DataLen][Payload]` | Standard data payload frame |
| `0x04` | `PKT_TELEPORT` | `[4B TargetIdx][4B SourceIdx][8B SendTimestampNano]` | Zero-byte content-addressed local clone instruction |
| `0x05` | `PKT_PHI_PARITY` | `[1B MemberCount][N*4B MemberIndices][2B ParityLen][XORPayload]` | Coprime-stride interleaved GF(2) erasure recovery frame |
| `0x06` | `PKT_FEEDBACK` | `[8B TxID][4B HighestContig][4B RecvCount][8B GradUs][8B QueueUs][2B NackCnt][N*4B Nacks]` | Selective repeat NACK bitmap + Kalman OWD gradient telemetry |
| `0x07` | `PKT_FIN` | `[8B TxID]` | Sender completion notification |
| `0x08` | `PKT_FIN_ACK` | `[8B TxID][1B VerifiedStatus]` | End-to-end SHA-256 verification confirmation |

---

## Quick Start

### Prerequisites
* **Go 1.20+** (Zero external library dependencies; uses only the Go standard library).

### 1. Run Built-In Chaos Self-Test (`selftest` mode)
OpenFIR includes an integrated Gilbert-Elliott burst-loss chaos simulator that automatically validates **both** a 16 MB mixed-entropy large file transfer and a **200-file nested directory tree** transfer under 8% burst packet loss:

```bash
go run openfir.go -mode selftest -sim-loss 0.08 -sim-burst 4 -sockets 8
```

### 2. Production Server & Client Usage

#### Build Binary
```bash
go build -o openfir openfir.go
```

#### Start Receiver (`server` mode)
```bash
./openfir -mode server -listen 0.0.0.0:9900 -out ./downloads -secret a37f92c819e4b50d
```

#### Send a Single Large File OR an Entire Directory of Small Files (`client` mode)
```bash
# Transfer a single large file
./openfir -mode client \
  -server 203.0.113.10:9900 \
  -file /path/to/large_archive.iso \
  -sockets 8 -init-mbps 100 -max-mbps 1000 -sim-loss 0

# Transfer a directory tree containing thousands of small files (Zero-RTT Virtual Extent)
./openfir -mode client \
  -server 203.0.113.10:9900 \
  -file /path/to/project_directory \
  -sockets 8 -init-mbps 100 -max-mbps 1000 -sim-loss 0
```

---

## Command-Line Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `selftest` | Execution mode: `selftest`, `server`, or `client` |
| `-listen` | `0.0.0.0:9900` | UDP listen address for `server` mode |
| `-out` | `./openfir_downloads` | Output directory for received files/directories in `server` mode |
| `-server` | `127.0.0.1:9900` | Target server UDP address for `client` mode |
| `-file` | `""` | Path to the file OR directory to transmit in `client` mode |
| `-sockets` | `8` | Number of concurrent local UDP sockets for multi-path striping |
| `-init-mbps` | `50.0` | Initial pacing rate in MB/s |
| `-max-mbps` | `1000.0` | Maximum pacing rate ceiling in MB/s |
| `-secret` | `a37f92c819e4b50d` | Pre-shared hex secret used to derive the 256-bit AES-GCM key |
| `-sim-loss` | `0.08` | Simulated Gilbert-Elliott packet loss ratio (`0` disables simulation) |
| `-sim-burst` | `4` | Simulated contiguous burst drop length |

---

## Cryptography & Export Control Notice

This repository utilizes standard `AES-256-GCM` (Authenticated Encryption with Associated Data) and `SHA-256` from the Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/sha256`) for packet confidentiality and authentication. This software is publicly available open-source encryption source code eligible for license exception **TSU / EAR § 742.15(b)** under the U.S. Export Administration Regulations.

---

## License

Copyright (c) 2026 The OpenFIR Authors. All rights reserved.

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.