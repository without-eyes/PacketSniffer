/**
    * @file: PcapFileReader.h
    * @author: without eyes
    *
    * This file contains main class of PacketSniffer application.
*/

#pragma once

#include <string>
#include <pcap/pcap.h>

enum FieldOffset {
    DESTINATION_MAC_ADDRESS_START = 0,
    DESTINATION_MAC_ADDRESS_END = 5,
    SOURCE_MAC_ADDRESS_START = 6,
    SOURCE_MAC_ADDRESS_END = 11,
    PROTOCOL_TYPE_START = 12,
    PROTOCOL_TYPE_END = 13,
    VERSION_AND_IHL = 14,
    TYPES_OF_SERVICE = 15,
    TOTAL_LENGTH_START = 16,
    TOTAL_LENGTH_END = 17,
    IDENTIFICATION_NUMBER_START = 18,
    IDENTIFICATION_NUMBER_END = 19,
    IP_FLAGS = 20,
    FRAGMENT_OFFSET_START = 20,
    FRAGMENT_OFFSET_END = 21,
    TIME_TO_LIVE = 22,
    PROTOCOL = 23,
    HEADER_CHECKSUM_START = 24,
    HEADER_CHECKSUM_END = 25,
    SOURCE_IP_ADDRESS_START = 26,
    SOURCE_IP_ADDRESS_END = 29,
    DESTINATION_IP_ADDRESS_START = 30,
    DESTINATION_IP_ADDRESS_END = 33,
    SOURCE_PORT_START = 34,
    SOURCE_PORT_END = 35,
    DESTINATION_PORT_START = 36,
    DESTINATION_PORT_END = 37,
    DATA = 38
};

class PcapFileReader {
public:
    PcapFileReader() = default;

    ~PcapFileReader() = default;

    void setPcapFile(const std::string &pcapFileName);

    void readPacket();

    std::string getMacAddress(FieldOffset startByte, FieldOffset endByte) const;

    std::string getProtocolType() const;

    int getProtocolVersion() const;

    int getHeaderLength() const;

    void printPacketInfo() const;

private:
    pcap_t* handle;
    pcap_pkthdr* header;
    const u_char* packet;
};