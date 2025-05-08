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

private:
    static std::string pathToFile;
};
