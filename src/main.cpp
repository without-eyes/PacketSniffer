#include "../include/PcapFileReader.h"

int main(int argc, char *argv[]) {
    PcapFileReader pcapFileReader;
    pcapFileReader.setPcapFile(argv[1]);
    pcapFileReader.readAllPackets();
}