/**
    * @file: Settings.h
    * @author: without eyes
    *
    * This file contains class that parses command arguments.
*/

#pragma once

#include <iostream>
#include <getopt.h>

class ArgumentsParser {
public:
    static void parseArguments(int argc, char *argv[]);

    static std::string getPathToFile();

    static std::string getSourceIpAddress();

    static std::string getDestinationIpAddress();

private:
    static std::string pathToFile;
    static std::string sourceIpAddress;
    static std::string destinationIpAddress;
};
