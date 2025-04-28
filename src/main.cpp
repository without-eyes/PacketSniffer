#include "../include/PcapFileReader.h"

int main(int argc, char const *argv[]) {
    PcapFileReader pcapFileReader;
    pcapFileReader.setPcapFile(argv[1]);
    pcapFileReader.readPacket();
    pcapFileReader.printPacketInfo();
}