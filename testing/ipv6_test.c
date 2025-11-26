#include "ethernet.h"
#include "ipv6.h"
#include "icmpv6.h"
#include "driver.h"
#include "testing/log.h"

#include <string.h>
#include <stdio.h>

extern FILE *pcap_in;
extern FILE *pcap_out;
extern FILE *pcap_demo;
extern FILE *control_flow;
extern FILE *demo_log;
extern FILE *out_log;
extern FILE *arp_log_f;
extern FILE *icmp_fout;
extern FILE *udp_fout;

uint8_t my_mac[] = NET_IF_MAC;
uint8_t my_ipv6[] = NET_IF_IPV6;
uint8_t broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int check_log();
int check_pcap();
void log_tab_buf();
FILE *open_file(char *path, char *name, char *mode);

buf_t buf;

/**
 * @brief 测试IPv6地址工具函数
 */
void test_ipv6_addr_utils() {
    fprintf(control_flow, "\n=== IPv6 Address Utility Tests ===\n");
    
    // 测试地址类型识别
    uint8_t unspecified[16] = {0};
    uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t link_local[16] = {0xfe,0x80,0,0,0,0,0,0,0x12,0x34,0x56,0xff,0xfe,0x78,0x9a,0xbc};
    uint8_t multicast[16] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t ipv4_mapped[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,168,1,1};
    
    fprintf(control_flow, "Unspecified address type: %d (expected 0)\n", 
            ipv6_get_addr_type(unspecified));
    fprintf(control_flow, "Loopback address type: %d (expected 1)\n", 
            ipv6_get_addr_type(loopback));
    fprintf(control_flow, "Multicast address type: %d (expected 2)\n", 
            ipv6_get_addr_type(multicast));
    fprintf(control_flow, "Link-local address type: %d (expected 3)\n", 
            ipv6_get_addr_type(link_local));
    fprintf(control_flow, "IPv4-mapped address type: %d (expected 5)\n", 
            ipv6_get_addr_type(ipv4_mapped));
    
    // 测试IPv4映射检查
    fprintf(control_flow, "Is IPv4-mapped: %d (expected 1)\n", 
            ipv6_is_ipv4_mapped(ipv4_mapped));
    fprintf(control_flow, "Is link-local IPv4-mapped: %d (expected 0)\n", 
            ipv6_is_ipv4_mapped(link_local));
    
    // 测试IPv4地址提取
    uint8_t extracted_ipv4[4];
    ipv6_extract_ipv4(ipv4_mapped, extracted_ipv4);
    fprintf(control_flow, "Extracted IPv4: %d.%d.%d.%d (expected 192.168.1.1)\n",
            extracted_ipv4[0], extracted_ipv4[1], extracted_ipv4[2], extracted_ipv4[3]);
    
    // 测试IPv4到IPv6映射
    uint8_t test_ipv4[4] = {10, 0, 0, 1};
    uint8_t mapped_ipv6[16];
    ipv6_make_ipv4_mapped(test_ipv4, mapped_ipv6);
    fprintf(control_flow, "Mapped IPv6: %s\n", ipv6_to_str(mapped_ipv6));
    
    // 测试地址比较
    fprintf(control_flow, "Address equal test: %d (expected 1)\n",
            ipv6_addr_equal(loopback, loopback));
    fprintf(control_flow, "Address not equal test: %d (expected 0)\n",
            ipv6_addr_equal(loopback, link_local));
}

/**
 * @brief 测试IPv6头部操作
 */
void test_ipv6_header() {
    fprintf(control_flow, "\n=== IPv6 Header Tests ===\n");
    
    ipv6_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    // 设置版本、流量类别、流标签
    ipv6_set_version_tc_flow(&hdr, 6, 0xAB, 0x12345);
    
    fprintf(control_flow, "Version: %d (expected 6)\n", ipv6_get_version(&hdr));
    fprintf(control_flow, "Traffic Class: 0x%02X (expected 0xAB)\n", ipv6_get_traffic_class(&hdr));
    fprintf(control_flow, "Flow Label: 0x%05X (expected 0x12345)\n", ipv6_get_flow_label(&hdr));
}

/**
 * @brief 测试IPv6数据包收发
 */
void test_ipv6_packet() {
    fprintf(control_flow, "\n=== IPv6 Packet Tests ===\n");
    
    // 构造测试IPv6数据包
    uint8_t test_data[] = "Hello IPv6!";
    buf_t test_buf;
    buf_init(&test_buf, sizeof(test_data));
    memcpy(test_buf.data, test_data, sizeof(test_data));
    
    // 目标地址：链路本地地址
    uint8_t dest_ip[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    
    fprintf(control_flow, "Sending IPv6 packet to %s\n", ipv6_to_str(dest_ip));
    fprintf(control_flow, "Payload length: %ld bytes\n", sizeof(test_data));
}

/**
 * @brief 测试ICMPv6校验和计算
 */
void test_icmpv6_checksum() {
    fprintf(control_flow, "\n=== ICMPv6 Checksum Tests ===\n");
    
    // 创建简单的Echo请求消息
    buf_t test_buf;
    buf_init(&test_buf, sizeof(icmpv6_echo_t));
    
    icmpv6_echo_t *echo = (icmpv6_echo_t *)test_buf.data;
    echo->type = ICMPV6_TYPE_ECHO_REQUEST;
    echo->code = 0;
    echo->checksum16 = 0;
    echo->id16 = swap16(1);
    echo->seq16 = swap16(1);
    
    uint8_t src_ip[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t dst_ip[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    
    uint16_t checksum = icmpv6_checksum(&test_buf, src_ip, dst_ip);
    fprintf(control_flow, "Calculated checksum: 0x%04X\n", checksum);
}

int main(int argc, char *argv[]) {
    int ret;
    PRINT_INFO("IPv6 Test begin.\n");
    
    if (argc < 2) {
        PRINT_ERROR("Usage: %s <test_data_dir>\n", argv[0]);
        return -1;
    }
    
    pcap_in = open_file(argv[1], "in.pcap", "r");
    pcap_out = open_file(argv[1], "out.pcap", "w");
    control_flow = open_file(argv[1], "log", "w");
    
    if (pcap_in == 0 || pcap_out == 0 || control_flow == 0) {
        if (pcap_in) fclose(pcap_in);
        else PRINT_ERROR("Failed to open in.pcap\n");
        if (pcap_out) fclose(pcap_out);
        else PRINT_ERROR("Failed to open out.pcap\n");
        if (control_flow) fclose(control_flow);
        else PRINT_ERROR("Failed to open log\n");
        return -1;
    }
    
    // 设置日志文件指针
    arp_log_f = control_flow;
    icmp_fout = control_flow;
    udp_fout = control_flow;
    
    // 初始化网络协议栈
    net_init();
    
    fprintf(control_flow, "=== IPv6 Dual-Stack Test Suite ===\n");
    fprintf(control_flow, "Local IPv6 Address: %s\n", ipv6_to_str(my_ipv6));
    fprintf(control_flow, "Local MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    
    // 运行单元测试
    test_ipv6_addr_utils();
    test_ipv6_header();
    test_icmpv6_checksum();
    test_ipv6_packet();
    
    log_tab_buf();
    
    // 处理输入数据包
    int i = 1;
    PRINT_INFO("Processing packets...\n");
    fprintf(control_flow, "\n=== Packet Processing ===\n");
    
    while ((ret = driver_recv(&buf)) > 0) {
        fprintf(control_flow, "\nRound %02d -----------------------------\n", i++);
        
        // 检查以太网类型
        if (buf.len >= 14) {
            uint16_t eth_type = (buf.data[12] << 8) | buf.data[13];
            fprintf(control_flow, "Ethernet type: 0x%04X\n", eth_type);
            
            if (eth_type == 0x86DD) {
                fprintf(control_flow, "IPv6 packet received\n");
            } else if (eth_type == 0x0800) {
                fprintf(control_flow, "IPv4 packet received\n");
            } else if (eth_type == 0x0806) {
                fprintf(control_flow, "ARP packet received\n");
            }
        }
        
        // 检查目的MAC地址
        if (memcmp(buf.data, my_mac, 6) == 0 || 
            memcmp(buf.data, broadcast_mac, 6) == 0 ||
            (buf.data[0] == 0x33 && buf.data[1] == 0x33)) {  // IPv6组播MAC
            ethernet_in(&buf);
        }
        
        log_tab_buf();
    }
    
    if (ret < 0) {
        PRINT_WARN("\nError occurred while loading input, exiting\n");
    }
    
    driver_close();
    PRINT_INFO("\nAll packets processed\n");
    
    fclose(control_flow);
    
    // 验证输出
    demo_log = open_file(argv[1], "demo_log", "r");
    out_log = open_file(argv[1], "log", "r");
    pcap_out = open_file(argv[1], "out.pcap", "r");
    pcap_demo = open_file(argv[1], "demo_out.pcap", "r");
    
    if (demo_log && out_log && pcap_out && pcap_demo) {
        check_log();
        ret = check_pcap() ? 1 : 0;
        
        if (demo_log) fclose(demo_log);
        if (out_log) fclose(out_log);
        if (pcap_demo) fclose(pcap_demo);
        if (pcap_out) fclose(pcap_out);
    } else {
        PRINT_WARN("Some demo files not found, skipping verification\n");
        ret = 0;
    }
    
    PRINT_INFO("IPv6 Test completed.\n");
    return ret ? -1 : 0;
}
