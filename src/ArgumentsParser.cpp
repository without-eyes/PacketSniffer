/**
* @file: Settings.h
    * @author: without eyes
    *
    * This file contains implementations of method that parses command arguments.
*/

#include "../include/ArgumentsParser.h"

#include <memory>

void ArgumentsParser::parseArguments(const int argc, char *argv[]) {
    int currentOption;
    auto longOptions = std::make_unique<option[]>(2);
    longOptions[0] = {"help", no_argument, nullptr, 'h'};
    longOptions[1] = {nullptr, 0, nullptr, 0}; // Null-terminator

    while ((currentOption = getopt_long(argc, argv, "h", longOptions.get(), nullptr)) != -1) {
        switch (currentOption) {
            case 'h': // help
                std::cout << "Usage: " << argv[0] << " [options] filename" << std::endl;
                std::cout << "  -h, --help        Show this help message" << std::endl;
                exit(EXIT_SUCCESS);

            default:
                std::cout << "Unknown option '" << currentOption << "'. Use -h for help." << std::endl;
                exit(EXIT_FAILURE);
        }
    }

    if (optind == argc) {
        std::cout << "No .pcap file was provided!" << std::endl;
        exit(EXIT_FAILURE);
    }
}
