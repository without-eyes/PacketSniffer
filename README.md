# Packet Sniffer

A lightweight and efficient packet sniffer written in C++ that analyzes PCAP files. This project uses [libpcap](https://www.tcpdump.org/manpages/pcap.3pcap.html) for low-level packet capturing and parsing, and demonstrates modern C++ practices along with command-line argument parsing.

## Features

* **Offline Analysis:**
  Read and analyze packets from PCAP files.

* **Detailed Packet Parsing:**
  Extract and display various protocol fields such as:

  * MAC addresses (source and destination)
  * EtherType (e.g., IPv4, ARP)
  * IP header fields (version, header length, time-to-live, etc.)
  * Protocol (TCP, UDP, ICMP, etc.)
  * Ports and IP addresses
  * Data/payload

* **Filtering Options:**
  Command-line options allow you to filter captured traffic by:
  * Source or destination IP (`--src <ip>`, `--dst <ip>`)
  * Port number (`--port <number>`)


## Getting Started

### Prerequisites

* **C++ Compiler:** Supporting C++17 (e.g. GCC 7+, Clang 7+)
* **CMake:** Version 3.10 or later
* **libpcap:** Development headers and library (often available via package manager)
* **Optional:** GoogleTest/GoogleMock for unit testing.

### Building the Project

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/without-eyes/PacketSniffer.git
   cd PacketSniffer
   ```

2. **Configure the Build with CMake:**

   ```bash
   mkdir build && cd build
   cmake ..
   ```

3. **Build the Project:**

   ```bash
   make
   ```

4. **Run the Program:**

     ```bash
     ./PacketSniffer -f /path/to/file.pcap
     ```


## Usage

### Command-Line Arguments

* **File Mode:**

  * `-f, --file <filename>`
    Reads packets from the specified PCAP file.

* **Filtering Options:**

  * `--src <ip>`: Show only packets from the source IP.
  * `--dst <ip>`: Show only packets to the destination IP.
  * `--port <number>`: Filter packets by port number (source or destination).

Run `./PacketSniffer -h` or `--help` for detailed usage information.

## Code Structure

* **src/**:
  Contains the core code including the packet parsing. The main class `PcapFileReader` handles loading PCAP files, extracting packet details, and printing information.

* **include/**:
  Header files for the project classes and utilities.

* **tests/**:
  Unit tests written using GoogleTest to validate parsing and filtering functionalities.

* **CMakeLists.txt**:
  The CMake build script, which includes options for building both the main application and tests.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
