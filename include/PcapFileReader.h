/**
    * @file: PcapFileReader.h
    * @author: without eyes
    *
    * This file contains main class of PacketSniffer application.
*/

#ifndef PCAPFILEREADER_H
#define PCAPFILEREADER_H

#include <string>
#include <pcap/pcap.h>

class PcapFileReader {
public:
    PcapFileReader() = default;

    ~PcapFileReader() = default;

    void setPcapFile(const std::string &pcapFileName);

    void readPacket();

private:
    pcap_t* handle;
    pcap_pkthdr* header;
    const u_char* packet;
};



#endif //PCAPFILEREADER_H
