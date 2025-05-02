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
        protocols[0] = "HOPOPT";
        protocols[1] = "ICMP";
        protocols[2] = "IGMP";
        protocols[3] = "GGP";
        protocols[4] = "IP-in-IP";
        protocols[5] = "ST";
        protocols[6] = "TCP";
        protocols[7] = "CBT";
        protocols[8] = "EGP";
        protocols[9] = "IGP";
        protocols[10] = "BBN-RCC-MON ";
        protocols[11] = "NVP-II";
        protocols[12] = "PUP";
        protocols[13] = "ARGUS";
        protocols[14] = "EMCON";
        protocols[15] = "XNET";
        protocols[16] = "CHAOS";
        protocols[17] = "UDP";
        protocols[18] = "MUX";
        protocols[19] = "DCN-MEAS";
        protocols[20] = "HMP";
        protocols[21] = "PRM";
        protocols[22] = "XNS-IDP";
        protocols[23] = "TRUNK-1";
        protocols[24] = "TRUNK-2";
        protocols[25] = "LEAF-1";
        protocols[26] = "LEAF-2";
        protocols[27] = "RDP";
        protocols[28] = "IRTP";
        protocols[29] = "ISO-TP4";
        protocols[30] = "NETBLT";
        protocols[31] = "MFE-NSP";
        protocols[32] = "MERIT-INP";
        protocols[33] = "DCCP";
        protocols[34] = "3PC";
        protocols[35] = "IDPR";
        protocols[36] = "XTP";
        protocols[37] = "DDP";
        protocols[38] = "IDPR-CMTP";
        protocols[39] = "TP++";
        protocols[40] = "IL";
        protocols[41] = "IPv6";
        protocols[42] = "SDRP";
        protocols[43] = "IPv6-Route";
        protocols[44] = "IPv6-Frag";
        protocols[45] = "IDRP";
        protocols[46] = "RSVP";
        protocols[47] = "GRE";
        protocols[48] = "DSR";
        protocols[49] = "BNA";
        protocols[50] = "ESP";
        protocols[51] = "AH";
        protocols[52] = "I-NLSP";
        protocols[53] = "SwIPe";
        protocols[54] = "NARP";
        protocols[55] = "MOBILE";
        protocols[56] = "TLSP";
        protocols[57] = "SKIP";
        protocols[58] = "IPv6-ICMP";
        protocols[59] = "IPv6-NoNxt";
        protocols[60] = "IPv6-Opts";
        protocols[61] = "-";
        protocols[62] = "CFTP";
        protocols[63] = "-";
        protocols[64] = "SAT-EXPAK";
        protocols[65] = "KRYPTOLAN";
        protocols[66] = "RVD";
        protocols[67] = "IPPC";
        protocols[68] = "-";
        protocols[69] = "SAT-MON";
        protocols[70] = "VISA";
        protocols[71] = "IPCU";
        protocols[72] = "CPNX";
        protocols[73] = "CPHB";
        protocols[74] = "WSN";
        protocols[75] = "PVP";
        protocols[76] = "BR-SAT-MON";
        protocols[77] = "SUN-ND";
        protocols[78] = "WB-MON";
        protocols[79] = "WB-EXPAK";
        protocols[81] = "VMTP";
        protocols[82] = "SECURE-VMTP";
        protocols[83] = "VINES";
        protocols[84] = "TTP/IPTM";
        protocols[85] = "NSFNET-IGP";
        protocols[86] = "DGP";
        protocols[87] = "TCF";
        protocols[88] = "EIGRP";
        protocols[89] = "OSPF";
        protocols[90] = "Sprite-RPC";
        protocols[91] = "LARP";
        protocols[92] = "MTP";
        protocols[93] = "AX.25";
        protocols[94] = "OS";
        protocols[95] = "MICP";
        protocols[96] = "SCC-SP";
        protocols[97] = "ETHERIP";
        protocols[98] = "ENCAP";
        protocols[99] = "-";
        protocols[100] = "GMTP";
        protocols[101] = "IFMP";
        protocols[102] = "PNNI";
        protocols[103] = "PIM";
        protocols[104] = "ARIS";
        protocols[105] = "SCPS";
        protocols[106] = "QNX";
        protocols[107] = "A/N";
        protocols[108] = "IPComp";
        protocols[109] = "SNP";
        protocols[110] = "Compaq-Peer";
        protocols[111] = "IPX-in-IP";
        protocols[112] = "VRRP";
        protocols[113] = "PGM";
        protocols[114] = "-";
        protocols[115] = "L2TP";
        protocols[116] = "DDX";
        protocols[117] = "IATP";
        protocols[118] = "STP";
        protocols[119] = "SRP";
        protocols[120] = "UTI";
        protocols[121] = "SMP";
        protocols[122] = "SM";
        protocols[123] = "PTP";
        protocols[124] = "IS-IS over IPv4";
        protocols[125] = "FIRE";
        protocols[126] = "CRTP";
        protocols[127] = "CRUDP";
        protocols[128] = "SSCOPMCE";
        protocols[129] = "IPLT";
        protocols[130] = "SPS";
        protocols[131] = "PIPE";
        protocols[132] = "SCTP";
        protocols[133] = "FC";
        protocols[134] = "RSVP-E2E-IGNORE";
        protocols[135] = "Mobility Header";
        protocols[136] = "UDPLite";
        protocols[137] = "MPLS-in-IP";
        protocols[138] = "manet";
        protocols[139] = "HIP";
        protocols[140] = "Shim6";
        protocols[141] = "WESP";
        protocols[142] = "ROHC";
        protocols[143] = "Ethernet";
        protocols[144] = "AGGFRAG";
        protocols[145] = "NSH";
        protocols[255] = "Reserved";
        for (int i = 146; i <= 254; i++) {
            protocols[i] = "-";
        }
    }

    std::stringstream protocolsStringStream;
    protocolsStringStream << protocols[static_cast<int>(packet[PROTOCOL])] << " (" << static_cast<int>(packet[PROTOCOL]) << ")";

    return protocolsStringStream.str();
}

void PcapFileReader::printPacketInfo() const {
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
    // TODO Header Checksum
    // TODO Source Address
    // TODO Destination Address
    // TODO Source Port
    // TODO Destination Port
    // TODO Data/Other
}
