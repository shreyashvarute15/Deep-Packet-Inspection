# Deep Packet Inspection (DPI) Engine

A C++17-based network packet analyzer for offline PCAP inspection, protocol parsing, application classification, connection tracking, and rule-based packet filtering.

## Overview

This project analyzes network traffic captured in PCAP files. It parses packet headers, extracts selected application-layer metadata, classifies recognizable services, and supports configurable filtering rules.

The project is intended for learning and demonstrating network programming, packet analysis, protocol parsing, and multithreaded C++ design.

## Features

- **PCAP processing:** Read captured packets and write filtered packet captures.
- **Protocol parsing:** Parse Ethernet, IPv4, TCP, and UDP headers.
- **Application metadata extraction:** Extract HTTP Host values and TLS Server Name Indication (SNI) when available in captured packets.
- **Application classification:** Map recognized hostnames to services such as YouTube, Netflix, Microsoft, Google, GitHub, and others.
- **Connection tracking:** Represent network flows using a five-tuple of source IP, destination IP, source port, destination port, and protocol.
- **Configurable filtering:** Apply IP-, domain-, and application-based rules where supported by the selected executable.
- **Multithreaded processing:** Includes components for distributing packet-processing work across threads.
- **Testing:** Unit and regression tests for protocol extraction, application classification, and filtering rules.

## Technology Stack

- C++17
- CMake
- GCC / MinGW-w64
- Python 3 for the sample PCAP generator and benchmark utility
- Git and GitHub

## Architecture

The main processing workflow is:

```text
Input PCAP
    |
    v
PCAP Reader
    |
    v
Ethernet / IPv4 / TCP / UDP Parser
    |
    v
Metadata Extraction
(HTTP Host / TLS SNI / DNS)
    |
    v
Application Classification
    |
    v
Filtering Rules
    |
    v
Analysis Report + Optional Filtered PCAP
```

The source is organized into reusable components for packet reading, parsing, SNI extraction, connection tracking, classification, filtering, and processing.

## Project Structure

```text
Deep-Packet-Inspection/
├── include/                  # C++ header files
├── src/                      # C++ implementation and tests
├── CMakeLists.txt            # CMake build configuration
├── test_dpi.pcap             # Sample packet capture
├── generate_test_pcap.py     # Sample PCAP generator
├── benchmark.py              # Benchmark utility
├── WINDOWS_SETUP.md          # Windows build instructions
├── FIXES_AND_VALIDATION.md   # Fixes and validation notes
├── README.md                 # Project overview
└── .gitignore
```

## Getting Started

### Prerequisites

- Windows with MSYS2 UCRT64, or a compatible C++17 development environment
- CMake
- GCC/G++ or another compatible C++17 compiler
- A terminal such as PowerShell

### Build on Windows

Open PowerShell in the project directory.

Configure the build using your installed MSYS2 UCRT64 toolchain:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;" + $env:Path

cmake -S . -B build-ucrt64 -G "MinGW Makefiles" `
  -DCMAKE_MAKE_PROGRAM="C:/msys64/ucrt64/bin/mingw32-make.exe" `
  -DCMAKE_C_COMPILER="C:/msys64/ucrt64/bin/gcc.exe" `
  -DCMAKE_CXX_COMPILER="C:/msys64/ucrt64/bin/g++.exe"
```

Build the project:

```powershell
cmake --build build-ucrt64 --parallel 4
```

### Run the Tests

```powershell
.\build-ucrt64\unit_tests.exe
```

The test suite includes checks for TLS SNI extraction, HTTP Host extraction, DNS query extraction, domain-boundary application classification, and filtering rules.

## Run the Analyzer

Analyze the included sample PCAP and generate a JSON report:

```powershell
.\build-ucrt64\packet_analyzer.exe --pcap test_dpi.pcap --output classification_report.json
```

To run the separate DPI engine with an application-blocking rule:

```powershell
.\build-ucrt64\dpi_engine.exe test_dpi.pcap filtered_test.pcap --block-app YouTube --lbs 1 --fps 1
```

The available arguments depend on the selected executable. Consult the source code and `WINDOWS_SETUP.md` for the supported options.

## Validation

The project has been built and tested on Windows using the MSYS2 UCRT64 GCC toolchain.

Validated results include:

- Successful compilation of all five CMake targets.
- Passing unit and regression test groups.
- Successful analysis of the sample PCAP containing 77 packets.
- Corrected domain-boundary classification for Microsoft and Netflix.
- Generation of a packet analysis report.

These results describe the included sample and test cases; they do not represent a performance benchmark or guarantee correct classification of every network capture.

## Important Limitations

- **Offline analysis:** The verified workflow processes saved PCAP files. It does not establish live network monitoring or operating-system-level traffic blocking.
- **TLS visibility:** SNI extraction depends on the captured handshake and the availability of the relevant hostname metadata. Encrypted ClientHello and incomplete captures can limit visibility.
- **Heuristic classification:** Application identification uses recognizable protocol metadata and hostname rules. It is not a guarantee of application identity.
- **Protocol scope:** The implemented parsers and extractors support only the protocol structures handled by the current code.
- **Performance:** Throughput and scalability must be measured with reproducible benchmarks before making performance claims.

Use packet captures that you own or are authorized to analyze.

## Future Improvements

- Separate DNS query reporting from application classification.
- Expand parser edge-case and malformed-packet tests.
- Improve reporting and visualization.
- Measure single-threaded and multithreaded performance.
- Add a web dashboard for uploading PCAP files and viewing analysis results.

## Acknowledgments

This project was developed from the Packet Analyzer project by Pratyush Narain. The repository and source code have been adapted and tested in a Windows development environment.

Original repository: https://github.com/perryvegehan/Packet_analyzer

## License

The original repository does not visibly include a license file. Check the original creator's reuse terms before adding a license or redistributing the project. No new license is asserted by this README.
