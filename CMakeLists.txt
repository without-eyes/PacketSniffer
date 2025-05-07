cmake_minimum_required(VERSION 3.28)
project(PacketSniffer)

set(CMAKE_CXX_STANDARD 17)

add_executable(PacketSniffer src/main.cpp src/PcapFileReader.cpp
        src/ArgumentsParser.cpp
        include/ArgumentsParser.h)

target_link_libraries(PacketSniffer pcap)

configure_file(numberToProtocol.txt ${CMAKE_CURRENT_BINARY_DIR}/numberToProtocol.txt COPYONLY)