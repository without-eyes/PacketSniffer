/**
    * @file: PcapFileReader.cpp
    * @author: without eyes
    *
    * This file contains implementation of PcapFileReader's methods.
*/
#include "../include/PcapFileReader.h"

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