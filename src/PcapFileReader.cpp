/**
    * @file: PcapFileReader.cpp
    * @author: without eyes
    *
    * This file contains implementation of PcapFileReader's methods.
*/
#include "../include/PcapFileReader.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <bits/ostream.tcc>

#include "../include/ArgumentsParser.h"

PcapFileReader::~PcapFileReader() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

void PcapFileReader::setPcapFile(const std::string &pcapFileName) {
    const auto errorBuffer = std::make_unique<char>(PCAP_ERRBUF_SIZE);
    handle = pcap_open_offline(pcapFileName.c_str(), errorBuffer.get());
    if (handle == nullptr) {
        std::cerr << errorBuffer.get() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void PcapFileReader::readAllPackets() {
    try {
        int count = 1;
        while (true) {
            readPacket();
            std::cout << "Packet Number: " << count++ << std::endl;
            printPacketInfo();
            std::cout << std::endl;
        }
    } catch (const std::exception &e) {
        exit(1);
    }
}

void PcapFileReader::readPacket() {
    const int result = pcap_next_ex(handle, &header, &packet);
    if (result == PCAP_ERROR) {
        throw std::runtime_error("Error reading packet!");
    }
    if (result == PCAP_ERROR_BREAK) {
        throw std::runtime_error("Reached end of file!");
    }
}

bool PcapFileReader::isPacketMatchesFilter() const {
    if (!ArgumentsParser::getSourceIpAddress().empty() &&
        getIpAddress(SOURCE_IP_ADDRESS_START, SOURCE_IP_ADDRESS_END) != ArgumentsParser::getSourceIpAddress()) {
        return false;
    }

    if (!ArgumentsParser::getDestinationIpAddress().empty() &&
        getIpAddress(DESTINATION_IP_ADDRESS_START, DESTINATION_IP_ADDRESS_END) != ArgumentsParser::getDestinationIpAddress()) {
        return false;
    }

    if (ArgumentsParser::getPort() &&
        getPort(SOURCE_PORT_START, SOURCE_PORT_END) != ArgumentsParser::getPort() &&
        getPort(DESTINATION_PORT_START, DESTINATION_PORT_END) != ArgumentsParser::getPort()) {
        return false;
    }

    return true;
}

std::string PcapFileReader::getMacAddress(const FieldOffset startByte, const FieldOffset endByte) const {
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
    packetProtocolStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[PROTOCOL_TYPE_START]);
    packetProtocolStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[PROTOCOL_TYPE_END]);
    const std::string packetProtocol = packetProtocolStringStream.str();

    std::stringstream resultStringStream;
    resultStringStream << protocols[packetProtocol] << " (0x" << packetProtocol << ")";

    return resultStringStream.str();
}

int PcapFileReader::getProtocolVersion() const {
    // Get 4 first bites of 15th byte, e.g., 01000101 AND 0b11110000 -> 01000000 >> 4 -> 0100 = 4
    return (static_cast<int>(packet[VERSION_AND_IHL]) & 240) >> 4;
}

int PcapFileReader::getHeaderLength() const {
    // Get 4 last bites of 15th byte, e.g., 01000101 AND 0b00001111 -> 0101 = 5 words = 20 bytes
    return static_cast<int>(packet[VERSION_AND_IHL]) & 15;
}

std::string PcapFileReader::getDifferentiatedServicesCodepoint() const {
    static std::unordered_map<int, std::string> dscpValues;
    if (dscpValues.empty()) {
        dscpValues[0] = "Default";
        dscpValues[8] = "Class Selector 1";
        dscpValues[10] = "AF11";
        dscpValues[18] = "AF21";
        dscpValues[26] = "AF31";
        dscpValues[46] = "Expedited Forwarding";
        for (int i = 48; i <= 63; i++) {
            dscpValues[i] = "CS6–CS7";
        }
    }

    std::stringstream dscpStringStream;
    dscpStringStream << dscpValues[static_cast<int>(packet[TYPES_OF_SERVICE]) & 252] << " (" << static_cast<int>(packet[TYPES_OF_SERVICE]) << ")";

    return dscpStringStream.str();
}

std::string PcapFileReader::getExplicitCongestionNotification() const {
    static std::unordered_map<int, std::string> ecnValues;
    if (ecnValues.empty()) {
        ecnValues[0] = "Not ECN-Capable";
        ecnValues[1] = "ECT(1)";
        ecnValues[2] = "ECT(0)";
        ecnValues[3] = "CE";
    }

    return ecnValues[static_cast<int>(packet[TYPES_OF_SERVICE]) & 2];
}

int PcapFileReader::getTotalLength() const {
    return (static_cast<int>(packet[TOTAL_LENGTH_START]) << 2) + static_cast<int>(packet[TOTAL_LENGTH_END]);
}

std::string PcapFileReader::getIdentificationNumber() const {
    std::stringstream identificationNumberStream;
    identificationNumberStream << "0x";
    identificationNumberStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[IDENTIFICATION_NUMBER_START]);
    identificationNumberStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[IDENTIFICATION_NUMBER_END]);
    identificationNumberStream << std::dec << " (" << (static_cast<int>(packet[IDENTIFICATION_NUMBER_START]) << 2) + static_cast<int>(packet[IDENTIFICATION_NUMBER_END]) << ")";
    return identificationNumberStream.str();
}

int PcapFileReader::getReservedBit() const {
    return (static_cast<int>(packet[IP_FLAGS]) & 128) >> 7;
}

int PcapFileReader::getDontFragmentBit() const {
    return (static_cast<int>(packet[IP_FLAGS]) & 64) >> 6;
}

int PcapFileReader::getMoreFragmentsBit() const {
    return (static_cast<int>(packet[IP_FLAGS]) & 32) >> 5;
}

int PcapFileReader::getFragmentsOffset() const {
    return ((static_cast<int>(packet[FRAGMENT_OFFSET_START]) & 31) << 2) + static_cast<int>(packet[FRAGMENT_OFFSET_END]);
}

int PcapFileReader::getTimeToLive() const {
    return static_cast<int>(packet[TIME_TO_LIVE]);
}

std::string PcapFileReader::getProtocol() const {
    static std::unordered_map<int, std::string> protocols;
    if (protocols.empty()) {
        std::string line;
        std::ifstream portToProtocolFile("numberToProtocol.txt");
        while (getline(portToProtocolFile, line)) {
            int port;
            std::string protocol;

            std::istringstream lineStream(line);
            lineStream >> port >> protocol;

            protocols[port] = protocol;
        }

        for (int i = 146; i <= 254; i++) {
            protocols[i] = "-";
        }
    }

    std::stringstream protocolsStringStream;
    protocolsStringStream << protocols[static_cast<int>(packet[PROTOCOL])] << " (" << static_cast<int>(packet[PROTOCOL]) << ")";

    return protocolsStringStream.str();
}

std::string PcapFileReader::getHeaderChecksum() const {
    std::stringstream headerChecksumStringStream;
    headerChecksumStringStream << "0x";
    headerChecksumStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[HEADER_CHECKSUM_START]);
    headerChecksumStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[HEADER_CHECKSUM_END]);
    return headerChecksumStringStream.str();
}

std::string PcapFileReader::getIpAddress(const FieldOffset startByte, const FieldOffset endByte) const {
    std::stringstream ipAddressStringStream;
    for (int i = startByte; i < endByte; i++) {
        ipAddressStringStream << static_cast<int>(packet[i]) << ".";
    }
    ipAddressStringStream << static_cast<int>(packet[endByte]);
    return ipAddressStringStream.str();
}

int PcapFileReader::getPort(const FieldOffset startByte, const FieldOffset endByte) const {
    return static_cast<int>(packet[startByte]) << 8 | static_cast<int>(packet[endByte]);
}

std::string PcapFileReader::getData() const {
    std::stringstream dataStringStream;
    for (int i = DATA; i < header->len; i++) {
        dataStringStream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[i]);
    }
    return dataStringStream.str();
}

void PcapFileReader::printPacketInfo() const {
    if (!isPacketMatchesFilter()) return;

    std::cout << "Size: " << header->len << std::endl;
    std::cout << "Time: " << std::put_time(std::localtime(&header->ts.tv_sec), "%c %Z") << std::endl;
    std::cout << "Destination MAC: " << getMacAddress(DESTINATION_MAC_ADDRESS_START, DESTINATION_MAC_ADDRESS_END) << std::endl;
    std::cout << "Source MAC: " << getMacAddress(SOURCE_MAC_ADDRESS_START, SOURCE_MAC_ADDRESS_END) << std::endl;
    std::cout << "Type: " << getProtocolType() << std::endl;
    std::cout << "Version: " << std::dec << getProtocolVersion() << std::endl;
    std::cout << "Header Length: " << getHeaderLength() << " (" << getHeaderLength() * 4 << " bytes)" << std::endl;
    std::cout << "Differentiated Services Codepoint: " << getDifferentiatedServicesCodepoint() << std::endl;
    std::cout << "Explicit Congestion Notification: " << getExplicitCongestionNotification() << std::endl;
    std::cout << "Total Length: " << getTotalLength() << std::endl;
    std::cout << "Identification Number: " << getIdentificationNumber() << std::endl;
    std::cout << "IP Flags:" << std::endl;
    std::cout << "\tReserved bit: " << getReservedBit() << std::endl;
    std::cout << "\tDon't fragment bit: " << getDontFragmentBit() << std::endl;
    std::cout << "\tMore fragments bit: " << getMoreFragmentsBit() << std::endl;
    std::cout << "Fragment Offset: " << getFragmentsOffset() << std::endl;
    std::cout << "Time to Live: " << getTimeToLive() << std::endl;
    std::cout << "Protocol: " << getProtocol() << std::endl;
    std::cout << "Header Checksum: " << getHeaderChecksum() << std::endl;
    std::cout << "Source Address: " << getIpAddress(SOURCE_IP_ADDRESS_START, SOURCE_IP_ADDRESS_END) << std::endl;
    std::cout << "Destination Address: " << getIpAddress(DESTINATION_IP_ADDRESS_START, DESTINATION_IP_ADDRESS_END) << std::endl;
    std::cout << "Source Port: " << getPort(SOURCE_PORT_START, SOURCE_PORT_END) << std::endl;
    std::cout << "Destination Port: " << getPort(DESTINATION_PORT_START, DESTINATION_PORT_END) << std::endl;
    std::cout << "Data: " << getData() << std::endl;
}
