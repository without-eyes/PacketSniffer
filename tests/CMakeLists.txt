cmake_minimum_required(VERSION 3.28)
project(PacketSnifferTests)

set(CMAKE_CXX_STANDARD 17)

add_executable(PacketSnifferTests main.cpp
        PcapFileReader_test.cpp
        ../src/PcapFileReader.cpp)

target_link_libraries(PacketSnifferTests pcap gtest gmock pthread)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../numberToProtocol.txt ${CMAKE_CURRENT_BINARY_DIR}/numberToProtocol.txt COPYONLY)
