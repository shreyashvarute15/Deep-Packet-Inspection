# Deep Packet Inspection (DPI) Engine

A C++17-based deep packet inspection engine with a React dashboard and Express.js backend for offline PCAP analysis, protocol parsing, application classification, connection tracking, and rule-based packet filtering.

## Overview

This project analyzes network traffic captured in PCAP files. The C++ engine parses supported packet headers, extracts selected application-layer metadata, classifies recognizable services, tracks connections, and supports configurable filtering rules.

A web interface built with React and Vite communicates with an Express.js backend to provide a graphical workflow for uploading PCAP files and viewing analysis results.

The project is intended for learning and demonstrating network programming, packet analysis, protocol parsing, web development, API integration, and multithreaded C++ design.

## Features

### C++ DPI Engine

- **PCAP processing:** Read captured packets and write filtered packet captures.
- **Protocol parsing:** Parse Ethernet, IPv4, TCP, and UDP headers.
- **Application metadata extraction:** Extract HTTP Host values and TLS Server Name Indication (SNI) when available in captured packets.
- **DNS extraction:** Extract supported DNS query information.
- **Application classification:** Map recognized hostnames to services such as YouTube, Netflix, Microsoft, Google, GitHub, and others.
- **Connection tracking:** Represent network flows using source IP, destination IP, source port, destination port, and protocol.
- **Configurable filtering:** Apply supported IP-, domain-, and application-based rules.
- **Multithreaded processing:** Includes components for distributing packet-processing work across threads.
- **Automated testing:** Unit and regression tests for protocol extraction, application classification, and filtering rules.

### Web Dashboard

- Upload PCAP files through a browser.
- View packet counts, data volume, connection counts, forwarded packets, and dropped packets.
- Visualize protocol distribution.
- Review application classification results.
- Inspect detected hosts and DNS queries.
- Export analysis results as JSON.
- Check backend API availability.

## Technology Stack

| Component | Technologies |
|---|---|
| DPI engine | C++17 |
| Build system | CMake |
| Compiler | GCC / MinGW-w64 |
| Backend | Node.js, Express.js |
| File uploads | Multer |
| Frontend | React, Vite, JavaScript, CSS |
| Charts | Recharts |
| Icons | Lucide React |
| API communication | HTTP, JSON |
| Test and utility scripts | Python 3 |
| Version control | Git, GitHub |

## Architecture

The application consists of three main components:

```text
                    User
                     |
                     v
          +----------------------+
          |    React Frontend    |
          |  Vite / JavaScript   |
          +----------------------+
                     |
               HTTP / JSON
                     |
                     v
          +----------------------+
          |    Express Backend   |
          |   PCAP Upload API    |
          +----------------------+
                     |
                     v
          +----------------------+
          |    C++ DPI Engine    |
          | Packet Parsing       |
          | Metadata Extraction  |
          | Application Rules    |
          | Connection Tracking  |
          +----------------------+
                     |
                     v
          +----------------------+
          | Analysis Report      |
          | JSON / Optional PCAP |
          +----------------------+
                     |
                     v
             React Dashboard
```

The C++ engine performs packet analysis. The backend manages HTTP requests and the analysis workflow, while the frontend presents the returned results.

The backend must be configured to invoke the correct compiled engine and interpret its output format for end-to-end analysis to work.

## Project Structure

```text
Deep-Packet-Inspection/
├── include/                  # C++ header files
├── src/                      # C++ implementation and tests
├── backend/
│   ├── server.js             # Express API server
│   ├── package.json          # Backend dependencies and scripts
│   ├── package-lock.json
│   └── .gitignore
├── frontend/
│   ├── public/                # Public frontend assets
│   ├── src/
│   │   ├── App.jsx            # Dashboard application
│   │   ├── App.css            # Dashboard styling
│   │   ├── index.css          # Global styling
│   │   └── main.jsx           # Frontend entry point
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   └── README.md
├── CMakeLists.txt             # C++ build configuration
├── generate_test_pcap.py      # Sample PCAP generator
├── benchmark.py               # Benchmark utility
├── WINDOWS_SETUP.md           # Windows build instructions
├── FIXES_AND_VALIDATION.md    # Fixes and validation notes
├── test_dpi.pcap              # Sample capture, if included
├── README.md
└── .gitignore
```

The tree documents the intended organization. Some files, including build outputs and sample captures, may be generated locally or excluded from version control.

## Getting Started

### Prerequisites

- Windows with MSYS2 UCRT64, or a compatible C++17 development environment
- CMake
- GCC/G++ or another compatible C++17 compiler
- Node.js and npm
- Python 3 for the supplied utility scripts
- PowerShell or another compatible terminal

### 1. Clone the Repository

```bash
git clone https://github.com/shreyashvarute15/Deep-Packet-Inspection.git
cd Deep-Packet-Inspection
```

### 2. Build the C++ Engine on Windows

Open PowerShell in the project directory.

Configure the MSYS2 UCRT64 toolchain:

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

For additional platform-specific instructions, see `WINDOWS_SETUP.md`.

### 3. Run the Tests

```powershell
.\build-ucrt64\unit_tests.exe
```

The existing test suite includes checks for TLS SNI extraction, HTTP Host extraction, DNS query extraction, domain-boundary application classification, and filtering rules.

### 4. Run the C++ Analyzer

If the sample capture and compiled executable are available, generate an analysis report:

```powershell
.\build-ucrt64\packet_analyzer.exe --pcap test_dpi.pcap --output classification_report.json
```

Run the separate DPI engine with an application-blocking rule:

```powershell
.\build-ucrt64\dpi_engine.exe test_dpi.pcap filtered_test.pcap --block-app YouTube --lbs 1 --fps 1
```

Available arguments depend on the selected executable. Consult the source code and `WINDOWS_SETUP.md` for supported options.

### 5. Start the Express Backend

Open a new terminal at the repository root:

```powershell
cd backend
npm install
npm start
```

Use the start command defined in `backend/package.json`. If no `start` script is configured, use the appropriate command for the server entry point.

The current local setup uses port `5000`.

### 6. Start the React Frontend

Open a separate terminal at the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite, typically:

`http://localhost:5173`

Keep both the frontend and backend running while testing the dashboard.

## API Endpoints

The Express backend exposes the following endpoints in the current local implementation:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Check backend availability |
| `POST` | `/api/analyze` | Upload a PCAP file for analysis |

The analysis endpoint accepts a multipart form upload with the field name `pcap`.

The frontend and backend must use matching endpoint paths, upload field names, response structures, and report formats.

## Validation

The original C++ engine documentation records the following validation results:

- Successful compilation of five CMake targets.
- Passing unit and regression test groups.
- Successful analysis of a sample PCAP containing 77 packets.
- Corrected domain-boundary classification for Microsoft and Netflix.
- Generation of a packet analysis report.

The web dashboard has also been run locally and displayed analysis results through the React interface.

These checks apply to the documented sample and test cases. The full web-to-engine workflow should be retested after changes to the backend, executable paths, report parsing, or deployment configuration.

## Important Limitations

- **Offline analysis:** The verified workflow processes saved PCAP files. It does not establish live network monitoring or operating-system-level traffic blocking.
- **TLS visibility:** SNI extraction depends on the captured handshake and available hostname metadata. Encrypted ClientHello and incomplete captures can limit visibility.
- **Heuristic classification:** Application identification relies on recognizable protocol metadata and hostname rules; it cannot guarantee application identity.
- **Protocol scope:** Parsers and extractors support only the packet and protocol structures implemented in the current source.
- **Performance:** Throughput and scalability should be evaluated with reproducible benchmarks before making performance claims.
- **Deployment:** The application requires the backend, the compiled DPI engine, and the frontend to be configured correctly. A locally working dashboard does not by itself confirm a successful production deployment.

## Future Improvements

- Separate DNS query reporting from application classification.
- Expand parser edge-case and malformed-packet tests.
- Improve report visualization and dashboard accessibility.
- Benchmark single-threaded and multithreaded performance.
- Strengthen upload validation and error handling.
- Configure production API URLs and deployment settings.
- Add integration tests covering PCAP upload through report generation.

## Security and Responsible Use

- Analyze packet captures that you own or are authorized to inspect.
- Do not commit credentials, secrets, private captures, or sensitive analysis reports.
- Keep `node_modules`, generated build files, and other unnecessary artifacts out of version control.
- Validate uploads and restrict access before exposing the backend publicly.

## Acknowledgments

This project was developed from the Packet Analyzer project by Pratyush Narain. The repository and source code have been adapted and tested in a Windows development environment.

Original repository: [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer)

Please preserve the original author's attribution and comply with the original repository's reuse terms.

## License

The original repository does not visibly include a license file. Check the original creator's reuse terms before adding a license or redistributing the adapted source code.
