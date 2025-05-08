/**
* @file: Settings.h
    * @author: without eyes
    *
    * This file contains implementations of method that parses command arguments.
*/

#include "../include/ArgumentsParser.h"

#include <memory>

std::string ArgumentsParser::pathToFile;
std::string ArgumentsParser::sourceIpAddress;

void ArgumentsParser::parseArguments(const int argc, char *argv[]) {
    int currentOption;
    auto longOptions = std::make_unique<option[]>(3);
    longOptions[0] = {"help", no_argument, nullptr, 'h'};
    longOptions[1] = {"file", required_argument, nullptr, 'f'};
    longOptions[1] = {"src", required_argument, nullptr, 's'};
    longOptions[2] = {nullptr, 0, nullptr, 0};

    while ((currentOption = getopt_long(argc, argv, "hf:s:", longOptions.get(), nullptr)) != -1) {
        switch (currentOption) {
            case 'h': // help
                std::cout << "Usage: " << argv[0] << " [options] filename" << std::endl;
                std::cout << "  -h, --help        Show this help message" << std::endl;
                std::cout << "  -f, --file        Set .pcap file from where packets will be read" << std::endl;
                exit(EXIT_SUCCESS);

            case 'f': // read from file
                pathToFile = optarg;
                break;

            case 's': // sort by source IP
                sourceIpAddress = optarg;
                break;

            default:
                std::cout << "Unknown option '" << currentOption << "'. Use -h for help." << std::endl;
                exit(EXIT_FAILURE);
        }
    }

    if (pathToFile.empty()) {
        std::cerr << "No .pcap file path provided. Use -f <filename> or --file=<filename>" << std::endl;
        exit(EXIT_FAILURE);
    }
}

std::string ArgumentsParser::getPathToFile() {
    return pathToFile;
}

std::string ArgumentsParser::getSourceIpAddress() {
    return sourceIpAddress;
}
