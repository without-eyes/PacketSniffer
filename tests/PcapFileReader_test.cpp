/**
    * @file: PcapFileReader_test.cpp
    * @author: without eyes
    *
    * This file contains Google tests to PcapFileReader's methods.
*/

#include "../include/PcapFileReader.h"

#include <gtest/gtest.h>
#include <pcap/pcap.h>

class PcapFileReaderTest : public ::testing::Test {
protected:
    PcapFileReader obj;
    pcap_pkthdr header;
    const u_char* packet;

    void SetUp() override {
        obj.setPcapFile("../../test.pcap");
        obj.readPacket();
    }
};

TEST_F(PcapFileReaderTest, MacAddress) {
    ASSERT_EQ(obj.getMacAddress(DESTINATION_MAC_ADDRESS_START, DESTINATION_MAC_ADDRESS_END), "00:60:97:12:2F:58");
    ASSERT_EQ(obj.getMacAddress(SOURCE_MAC_ADDRESS_START, SOURCE_MAC_ADDRESS_END), "00:20:AF:BA:78:65");
}

TEST_F(PcapFileReaderTest, ProtocolType) {
    ASSERT_EQ(obj.getProtocolType(), "IPv4 (0x0800)");
}

TEST_F(PcapFileReaderTest, ProtocolVersion) {
    ASSERT_EQ(obj.getProtocolVersion(), 4);
}

TEST_F(PcapFileReaderTest, HeaderLength) {
    ASSERT_EQ(obj.getHeaderLength(), 5);
}

TEST_F(PcapFileReaderTest, DifferentiatedServicesCodepoint) {
    ASSERT_EQ(obj.getDifferentiatedServicesCodepoint(), "Default (0)");
}

TEST_F(PcapFileReaderTest, ExplicitCongestionNotification) {
    ASSERT_EQ(obj.getExplicitCongestionNotification(), "Not ECN-Capable");
}

TEST_F(PcapFileReaderTest, TotalLength) {
    ASSERT_EQ(obj.getTotalLength(), 38);
}

TEST_F(PcapFileReaderTest, ReservedBit) {
    ASSERT_EQ(obj.getReservedBit(), 0);
}

TEST_F(PcapFileReaderTest, DontFragmentBit) {
    ASSERT_EQ(obj.getDontFragmentBit(), 0);
}

TEST_F(PcapFileReaderTest, MoreFragmentsBit) {
    ASSERT_EQ(obj.getMoreFragmentsBit(), 1);
}

TEST_F(PcapFileReaderTest, FragmentOffset) {
    ASSERT_EQ(obj.getFragmentsOffset(), 0);
}

TEST_F(PcapFileReaderTest, TimeToLive) {
    ASSERT_EQ(obj.getTimeToLive(), 64);
}

TEST_F(PcapFileReaderTest, Protocol) {
    ASSERT_EQ(obj.getProtocol(), "UDP (17)");
}

TEST_F(PcapFileReaderTest, HeaderChecksum) {
    ASSERT_EQ(obj.getHeaderChecksum(), "0x1AF2");
}

TEST_F(PcapFileReaderTest, IpAddress) {
    ASSERT_EQ(obj.getIpAddress(SOURCE_IP_ADDRESS_START, SOURCE_IP_ADDRESS_END), "164.1.123.163");
    ASSERT_EQ(obj.getIpAddress(DESTINATION_IP_ADDRESS_START, DESTINATION_IP_ADDRESS_END), "164.1.123.61");
}

TEST_F(PcapFileReaderTest, Port) {
    ASSERT_EQ(obj.getPort(SOURCE_PORT_START, SOURCE_PORT_END), 123);
    ASSERT_EQ(obj.getPort(DESTINATION_PORT_START, DESTINATION_PORT_END), 137);
}

TEST_F(PcapFileReaderTest, Data) {
    ASSERT_EQ(obj.getData(), "0012BFE2000000000000000000000000000000000000");
}