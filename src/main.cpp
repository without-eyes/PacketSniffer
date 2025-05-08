#include "../include/ArgumentsParser.h"
#include "../include/PcapFileReader.h"

int main(const int argc, char *argv[]) {
    ArgumentsParser::parseArguments(argc, argv);
    PcapFileReader pcapFileReader{};
    pcapFileReader.run();
}