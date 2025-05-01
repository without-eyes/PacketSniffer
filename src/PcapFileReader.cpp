/**
    * @file: PcapFileReader.cpp
    * @author: without eyes
    *
    * This file contains implementation of PcapFileReader's methods.
*/
#include "../include/PcapFileReader.h"

#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <bits/ostream.tcc>

void PcapFileReader::setPcapFile(const std::string &pcapFileName) {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(pcapFileName.c_str(), errorBuffer);
    if (handle == nullptr) {
        std::cerr << errorBuffer << std::endl;
        exit(EXIT_FAILURE);
    }
}

void PcapFileReader::readPacket() {
    const int result = pcap_next_ex(handle, &header, &packet);
    if (result == PCAP_ERROR) {
        std::cerr << "Error reading packet!" << std::endl;
        exit(1);
    }
}

std::string PcapFileReader::getMacAddress(const int startByte, const int endByte) const {
    std::stringstream macAddressStreamString;
    for (int i = startByte; i < endByte; i++) {
        macAddressStreamString << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[i]) << ":";
    }
    macAddressStreamString << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[endByte]);
    return macAddressStreamString.str();
}

std::string PcapFileReader::getProtocolType() const {
    static std::unordered_map<std::string, std::string> protocols;
    if (protocols.empty()) {
        protocols["0800"] = "IPv4";
        protocols["86DD"] = "IPv6";
        protocols["0806"] = "ARP";
        protocols["8100"] = "VLAN-tagged";
        protocols["88CC"] = "LLDP";
        protocols["8847"] = "MPLS";
    }

    std::stringstream packetProtocolStringStream;
    packetProtocolStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[12]);
    packetProtocolStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[13]);
    const std::string packetProtocol = packetProtocolStringStream.str();

    std::stringstream resultStringStream;
    resultStringStream << protocols[packetProtocol] << " (0x" << packetProtocol << ")";

    return resultStringStream.str();
}

int PcapFileReader::getProtocolVersion() const {
    // Get 4 first bites of 15th byte, e.g., 01000101 AND 0b11110000 -> 01000000 >> 4 -> 0100 = 4
    return (static_cast<int>(packet[14]) & 240) >> 4;
}

int PcapFileReader::getHeaderLength() const {
    // Get 4 last bites of 15th byte, e.g., 01000101 AND 0b00001111 -> 0101 = 5 words = 20 bytes
    return static_cast<int>(packet[14]) & 15;
}

void PcapFileReader::printPacketInfo() const {
    std::cout << "Size: " << header->len << std::endl;
    std::cout << "Time: " << std::put_time(std::localtime(&header->ts.tv_sec), "%c %Z") << std::endl;
    std::cout << "Destination MAC: " << getMacAddress(0, 5) << std::endl;
    std::cout << "Source MAC: " << getMacAddress(6, 11) << std::endl;
    std::cout << "Type: " << getProtocolType() << std::endl;
    std::cout << "Version: " << std::dec << getProtocolVersion() << std::endl;
    std::cout << "Header Length: " << getHeaderLength() << " (" << getHeaderLength() * 4 << " bytes)" << std::endl;
    // TODO Types of Service
    // TODO Total Length
    // TODO Identification Number
    // TODO IP Flags
    // TODO Fragment Offset
    // TODO Time to Live
    // TODO Protocol
    // TODO Header Checksum
    // TODO Source Address
    // TODO Destination Address
    // TODO Source Port
    // TODO Destination Port
    // TODO Data/Other
}
