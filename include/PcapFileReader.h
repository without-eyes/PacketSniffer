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

    std::string getMacAddress(int startByte, int endByte) const;

    std::string getProtocolType() const;

    void printProtocolVersion() const;

    void printHeaderLength() const;

    void printPacketInfo() const;

private:
    pcap_t* handle;
    pcap_pkthdr* header;
    const u_char* packet;
};



#endif //PCAPFILEREADER_H
