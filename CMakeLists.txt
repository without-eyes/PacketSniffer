cmake_minimum_required(VERSION 3.28)
project(PacketSniffer)

set(CMAKE_CXX_STANDARD 17)

add_executable(PacketSniffer src/main.cpp src/PcapFileReader.cpp)

target_link_libraries(PacketSniffer pcap)