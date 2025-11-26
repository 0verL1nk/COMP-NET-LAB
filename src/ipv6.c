#include "ipv6.h"
#include "ethernet.h"
#include "net.h"
#include "icmpv6.h"

#include <stdio.h>
#include <string.h>

// 本机IPv6地址（链路本地地址，基于MAC地址生成）
uint8_t net_if_ipv6[NET_IPV6_LEN] = NET_IF_IPV6;

// 特殊地址定义
uint8_t ipv6_unspecified[NET_IPV6_LEN] = {0};  // ::
uint8_t ipv6_loopback[NET_IPV6_LEN] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};  // ::1
uint8_t ipv6_all_nodes_multicast[NET_IPV6_LEN] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};  // ff02::1

/**
 * @brief 获取IPv6头部的版本字段
 */
uint8_t ipv6_get_version(const ipv6_hdr_t *hdr) {
    return (swap32(hdr->version_tc_flow) >> 28) & 0x0F;
}

/**
 * @brief 获取IPv6头部的流量类别
 */
uint8_t ipv6_get_traffic_class(const ipv6_hdr_t *hdr) {
    return (swap32(hdr->version_tc_flow) >> 20) & 0xFF;
}

/**
 * @brief 获取IPv6头部的流标签
 */
uint32_t ipv6_get_flow_label(const ipv6_hdr_t *hdr) {
    return swap32(hdr->version_tc_flow) & 0x000FFFFF;
}

/**
 * @brief 设置IPv6头部的版本、流量类别和流标签
 */
void ipv6_set_version_tc_flow(ipv6_hdr_t *hdr, uint8_t version, uint8_t tc, uint32_t flow) {
    uint32_t value = ((uint32_t)version << 28) | ((uint32_t)tc << 20) | (flow & 0x000FFFFF);
    hdr->version_tc_flow = swap32(value);
}

/**
 * @brief 比较两个IPv6地址是否相等
 */
int ipv6_addr_equal(const uint8_t *ip1, const uint8_t *ip2) {
    return memcmp(ip1, ip2, NET_IPV6_LEN) == 0;
}

/**
 * @brief 获取IPv6地址类型
 */
ipv6_addr_type_t ipv6_get_addr_type(const uint8_t *ip) {
    // 检查未指定地址 ::
    int all_zero = 1;
    for (int i = 0; i < NET_IPV6_LEN; i++) {
        if (ip[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        return IPV6_ADDR_UNSPECIFIED;
    }
    
    // 检查回环地址 ::1
    int is_loopback = 1;
    for (int i = 0; i < NET_IPV6_LEN - 1; i++) {
        if (ip[i] != 0) {
            is_loopback = 0;
            break;
        }
    }
    if (is_loopback && ip[15] == 1) {
        return IPV6_ADDR_LOOPBACK;
    }
    
    // 检查组播地址 ff00::/8
    if (ip[0] == 0xff) {
        return IPV6_ADDR_MULTICAST;
    }
    
    // 检查链路本地地址 fe80::/10
    if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) {
        return IPV6_ADDR_LINK_LOCAL;
    }
    
    // 检查IPv4映射地址 ::ffff:w.x.y.z
    if (ipv6_is_ipv4_mapped(ip)) {
        return IPV6_ADDR_IPV4_MAPPED;
    }
    
    // 检查IPv4兼容地址 ::w.x.y.z (已废弃，但仍支持)
    int ipv4_compatible = 1;
    for (int i = 0; i < 12; i++) {
        if (ip[i] != 0) {
            ipv4_compatible = 0;
            break;
        }
    }
    if (ipv4_compatible && (ip[12] != 0 || ip[13] != 0 || ip[14] != 0 || ip[15] != 0)) {
        return IPV6_ADDR_IPV4_COMPATIBLE;
    }
    
    // 其他地址视为全局地址
    return IPV6_ADDR_GLOBAL;
}

/**
 * @brief 检查是否为IPv4映射的IPv6地址 (::ffff:w.x.y.z)
 */
int ipv6_is_ipv4_mapped(const uint8_t *ipv6) {
    // 前80位为0，接下来16位为ffff
    for (int i = 0; i < 10; i++) {
        if (ipv6[i] != 0) return 0;
    }
    return (ipv6[10] == 0xff && ipv6[11] == 0xff);
}

/**
 * @brief 从IPv4映射地址中提取IPv4地址
 */
void ipv6_extract_ipv4(const uint8_t *ipv6, uint8_t *ipv4) {
    memcpy(ipv4, &ipv6[12], NET_IP_LEN);
}

/**
 * @brief 将IPv4地址转换为IPv4映射的IPv6地址
 */
void ipv6_make_ipv4_mapped(const uint8_t *ipv4, uint8_t *ipv6) {
    memset(ipv6, 0, 10);
    ipv6[10] = 0xff;
    ipv6[11] = 0xff;
    memcpy(&ipv6[12], ipv4, NET_IP_LEN);
}

/**
 * @brief 将IPv6地址转换为字符串表示
 */
char *ipv6_to_str(const uint8_t *ip) {
    static char str[40];  // xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx + \0
    
    // 检查是否为IPv4映射地址
    if (ipv6_is_ipv4_mapped(ip)) {
        sprintf(str, "::ffff:%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);
        return str;
    }
    
    // 标准IPv6格式
    sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    
    return str;
}

/**
 * @brief 处理收到的IPv6数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源MAC地址
 */
void ipv6_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度
    if (buf->len < sizeof(ipv6_hdr_t)) {
        return;  // 数据包不完整，丢弃
    }
    
    // 获取IPv6头部
    ipv6_hdr_t *hdr = (ipv6_hdr_t *)buf->data;
    
    // Step2: 验证版本号
    uint8_t version = ipv6_get_version(hdr);
    if (version != IPV6_VERSION) {
        return;  // 版本号不正确，丢弃
    }
    
    // Step3: 验证载荷长度
    uint16_t payload_len = swap16(hdr->payload_len16);
    if (payload_len > buf->len - IPV6_HDR_LEN) {
        return;  // 载荷长度超过实际数据长度，丢弃
    }
    
    // Step4: 检查目的地址
    // 检查是否发往本机的单播地址
    int is_for_us = ipv6_addr_equal(hdr->dst_ip, net_if_ipv6);
    
    // 检查是否是组播地址（本机需要处理的组播）
    if (!is_for_us && hdr->dst_ip[0] == 0xff) {
        // 检查是否是所有节点组播地址 ff02::1
        if (ipv6_addr_equal(hdr->dst_ip, ipv6_all_nodes_multicast)) {
            is_for_us = 1;
        }
        // 可以添加更多组播地址的处理
    }
    
    if (!is_for_us) {
        return;  // 不是发往本机的数据包，丢弃
    }
    
    // Step5: 移除填充（如果有）
    uint16_t total_len = IPV6_HDR_LEN + payload_len;
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }
    
    // Step6: 保存下一头部类型，用于协议分发
    uint8_t next_header = hdr->next_header;
    
    // 保存源地址（用于传递给上层）
    uint8_t src_ip[NET_IPV6_LEN];
    memcpy(src_ip, hdr->src_ip, NET_IPV6_LEN);
    
    // Step7: 移除IPv6头部
    buf_remove_header(buf, IPV6_HDR_LEN);
    
    // Step8: 根据下一头部类型分发到上层协议
    int result = -1;
    switch (next_header) {
        case IPV6_NEXT_HEADER_ICMPV6:
            // ICMPv6 处理
            #ifdef ICMPV6
            icmpv6_in(buf, src_ip);
            result = 0;
            #endif
            break;
            
        case IPV6_NEXT_HEADER_TCP:
            // TCP 处理 - 可以复用现有TCP实现
            #ifdef TCP
            result = net_in(buf, NET_PROTOCOL_TCP, src_ip);
            #endif
            break;
            
        case IPV6_NEXT_HEADER_UDP:
            // UDP 处理 - 可以复用现有UDP实现
            #ifdef UDP
            result = net_in(buf, NET_PROTOCOL_UDP, src_ip);
            #endif
            break;
            
        default:
            // 不支持的协议
            result = -1;
            break;
    }
    
    // 如果协议不被支持，可以发送ICMPv6参数问题消息
    if (result < 0) {
        // 重新加入头部，发送ICMPv6错误消息
        buf_add_header(buf, IPV6_HDR_LEN);
        #ifdef ICMPV6
        // icmpv6_param_problem(buf, src_ip, ICMPV6_PARAM_NEXT_HEADER, 6);
        #endif
    }
}

/**
 * @brief 发送IPv6数据包
 * 
 * @param buf 要发送的数据
 * @param ip 目标IPv6地址
 * @param next_header 下一头部类型
 */
void ipv6_out(buf_t *buf, uint8_t *ip, ipv6_next_header_t next_header) {
    // Step1: 添加IPv6头部空间
    buf_add_header(buf, IPV6_HDR_LEN);
    
    // Step2: 填写IPv6头部
    ipv6_hdr_t *hdr = (ipv6_hdr_t *)buf->data;
    
    // 设置版本(6)、流量类别(0)、流标签(0)
    ipv6_set_version_tc_flow(hdr, IPV6_VERSION, 0, 0);
    
    // 载荷长度（不包含IPv6头部）
    hdr->payload_len16 = swap16(buf->len - IPV6_HDR_LEN);
    
    // 下一头部类型
    hdr->next_header = next_header;
    
    // 跳数限制
    hdr->hop_limit = IPV6_DEFAULT_HOP_LIMIT;
    
    // 源地址（本机IPv6地址）
    memcpy(hdr->src_ip, net_if_ipv6, NET_IPV6_LEN);
    
    // 目标地址
    memcpy(hdr->dst_ip, ip, NET_IPV6_LEN);
    
    // Step3: 确定目标MAC地址并发送
    // IPv6使用邻居发现协议(NDP)而不是ARP
    // 对于链路本地地址，可以直接从IPv6地址推导MAC地址
    // 对于组播地址，使用特殊的组播MAC地址
    
    uint8_t dst_mac[NET_MAC_LEN];
    
    if (ip[0] == 0xff) {
        // 组播地址：MAC = 33:33:xx:xx:xx:xx (后4字节取自IPv6组播地址后32位)
        dst_mac[0] = 0x33;
        dst_mac[1] = 0x33;
        dst_mac[2] = ip[12];
        dst_mac[3] = ip[13];
        dst_mac[4] = ip[14];
        dst_mac[5] = ip[15];
    } else if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) {
        // 链路本地地址：从EUI-64格式提取MAC地址
        // fe80::xxxx:xxff:fexx:xxxx -> MAC地址
        dst_mac[0] = ip[8] ^ 0x02;  // 反转U/L位
        dst_mac[1] = ip[9];
        dst_mac[2] = ip[10];
        // 跳过 ff:fe
        dst_mac[3] = ip[13];
        dst_mac[4] = ip[14];
        dst_mac[5] = ip[15];
    } else {
        // 其他地址：应该使用NDP查找，这里简化处理
        // 实际应该调用邻居发现缓存或发送邻居请求
        // 暂时使用广播
        memset(dst_mac, 0xff, NET_MAC_LEN);
    }
    
    // 通过以太网层发送
    ethernet_out(buf, dst_mac, NET_PROTOCOL_IPV6);
}

/**
 * @brief 初始化IPv6协议
 */
void ipv6_init() {
    // 注册IPv6协议处理函数
    net_add_protocol(NET_PROTOCOL_IPV6, ipv6_in);
    
    // 生成链路本地地址（基于MAC地址的EUI-64格式）
    // fe80::xxxx:xxff:fexx:xxxx
    net_if_ipv6[0] = 0xfe;
    net_if_ipv6[1] = 0x80;
    memset(&net_if_ipv6[2], 0, 6);  // 中间6字节为0
    
    // 使用EUI-64格式从MAC地址生成接口标识符
    net_if_ipv6[8] = net_if_mac[0] ^ 0x02;  // 反转U/L位
    net_if_ipv6[9] = net_if_mac[1];
    net_if_ipv6[10] = net_if_mac[2];
    net_if_ipv6[11] = 0xff;
    net_if_ipv6[12] = 0xfe;
    net_if_ipv6[13] = net_if_mac[3];
    net_if_ipv6[14] = net_if_mac[4];
    net_if_ipv6[15] = net_if_mac[5];
    
    printf("IPv6 initialized with address: %s\n", ipv6_to_str(net_if_ipv6));
}
