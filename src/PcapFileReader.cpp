/**
    * @file: PcapFileReader.cpp
    * @author: without eyes
    *
    * This file contains implementation of PcapFileReader's methods.
*/
#include "../include/PcapFileReader.h"

#include <iomanip>
#include <iostream>
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

void PcapFileReader::printMacAddress(const int startByte, const int endByte) const {
    for (int i = startByte; i < endByte; i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[i]) << ":";
    }
    std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << static_cast<int>(packet[endByte]) << std::endl;
}

void PcapFileReader::printPacketInfo() const {
    std::cout << "Size: " << header->len << std::endl;
    std::cout << "Time: " << std::put_time(std::localtime(&header->ts.tv_sec), "%c %Z") << std::endl;

    std::cout << "Destination MAC: ";
    printMacAddress(0, 5);

    std::cout << "Source MAC: ";
    printMacAddress(6, 11);
}
