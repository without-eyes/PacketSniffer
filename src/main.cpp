#include <iomanip>
#include <iostream>
#include <pcap/pcap.h>

enum READER_ERROR {
    OK = 0,
    BAD_ARGUMENTS,
    OPEN_FILE,
    READ_FILE,
};

int main(int argc, char const *argv[])
{
    if (argc != 2) {
        std::cerr << "this program needs file name as input argument" << std::endl;
        return READER_ERROR::BAD_ARGUMENTS;
    }

    bool print_debug_info = true;

    char errbuf[PCAP_ERRBUF_SIZE];
    std::string fname(argv[1]);
    // https://www.tcpdump.org/manpages/pcap_open_offline.3pcap.html
    pcap_t* handle = pcap_open_offline(fname.c_str(), errbuf);
    if (handle == NULL) {
        std::cerr << errbuf << std::endl;
        return READER_ERROR::OPEN_FILE;
    }

    pcap_pkthdr* header;
    const u_char* packet;

    int result = pcap_next_ex(handle, &header, &packet);
    if (result == PCAP_ERROR) {
        std::cerr << "error" << std::endl;
        return READER_ERROR::READ_FILE;
    }
    if (result == PCAP_ERROR_BREAK) {
        std::cout << "stop" << std::endl;
    }


    if (print_debug_info) {
        // https://www.tcpdump.org/manpages/pcap.3pcap.html
        std::cout << "Packet size: " << header->len << std::endl;
        std::cout << "Number of bytes: " << header->caplen << std::endl;
        const std::time_t t = header->ts.tv_sec;
        std::cout << std::put_time(std::localtime(&t), "%c %Z") << std::endl;
        for (int i = 0; i < header->caplen; ++i) {
            std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase
                << static_cast<int>(packet[i]) << " ";
        }
        std::cout << std::endl;
    }
    pcap_close(handle);

    return READER_ERROR::OK;
}