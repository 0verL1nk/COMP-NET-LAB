#ifndef IPV6_H
#define IPV6_H

#include "net.h"

#define NET_IPV6_LEN 16  // IPv6 地址长度（128位 = 16字节）

#pragma pack(1)
/**
 * @brief IPv6 头部结构（固定40字节）
 * 
 * IPv6头部格式：
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version| Traffic Class |           Flow Label                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload Length        |  Next Header  |   Hop Limit |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct ipv6_hdr {
    uint32_t version_tc_flow;       // 版本(4位) + 流量类别(8位) + 流标签(20位)
    uint16_t payload_len16;         // 载荷长度（不包含头部）
    uint8_t next_header;            // 下一个头部（类似IPv4的协议字段）
    uint8_t hop_limit;              // 跳数限制（类似IPv4的TTL）
    uint8_t src_ip[NET_IPV6_LEN];   // 源IPv6地址
    uint8_t dst_ip[NET_IPV6_LEN];   // 目标IPv6地址
} ipv6_hdr_t;
#pragma pack()

#define IPV6_HDR_LEN 40             // IPv6 头部固定长度
#define IPV6_VERSION 6              // IPv6 版本号
#define IPV6_DEFAULT_HOP_LIMIT 64   // 默认跳数限制

// IPv6 下一头部类型（Next Header）定义
typedef enum ipv6_next_header {
    IPV6_NEXT_HEADER_HOPOPT = 0,    // 逐跳选项
    IPV6_NEXT_HEADER_ICMPV6 = 58,   // ICMPv6
    IPV6_NEXT_HEADER_TCP = 6,       // TCP
    IPV6_NEXT_HEADER_UDP = 17,      // UDP
    IPV6_NEXT_HEADER_NONE = 59,     // 无下一头部
    IPV6_NEXT_HEADER_FRAGMENT = 44, // 分片头部
} ipv6_next_header_t;

// IPv6 地址类型
typedef enum ipv6_addr_type {
    IPV6_ADDR_UNSPECIFIED,    // 未指定地址 (::)
    IPV6_ADDR_LOOPBACK,       // 回环地址 (::1)
    IPV6_ADDR_MULTICAST,      // 组播地址 (ff00::/8)
    IPV6_ADDR_LINK_LOCAL,     // 链路本地地址 (fe80::/10)
    IPV6_ADDR_GLOBAL,         // 全局地址
    IPV6_ADDR_IPV4_MAPPED,    // IPv4映射地址 (::ffff:w.x.y.z)
    IPV6_ADDR_IPV4_COMPATIBLE,// IPv4兼容地址 (::w.x.y.z)
} ipv6_addr_type_t;

// 全局变量声明
extern uint8_t net_if_ipv6[NET_IPV6_LEN];   // 本机IPv6地址
extern uint8_t ipv6_unspecified[NET_IPV6_LEN]; // 未指定地址 ::
extern uint8_t ipv6_loopback[NET_IPV6_LEN];    // 回环地址 ::1
extern uint8_t ipv6_all_nodes_multicast[NET_IPV6_LEN]; // 所有节点组播地址

// 函数声明
void ipv6_init();
void ipv6_in(buf_t *buf, uint8_t *src_mac);
void ipv6_out(buf_t *buf, uint8_t *ip, ipv6_next_header_t next_header);

// IPv6 地址工具函数
ipv6_addr_type_t ipv6_get_addr_type(const uint8_t *ip);
int ipv6_is_ipv4_mapped(const uint8_t *ipv6);
void ipv6_extract_ipv4(const uint8_t *ipv6, uint8_t *ipv4);
void ipv6_make_ipv4_mapped(const uint8_t *ipv4, uint8_t *ipv6);
int ipv6_addr_equal(const uint8_t *ip1, const uint8_t *ip2);
char *ipv6_to_str(const uint8_t *ip);

// IPv6 头部工具函数
uint8_t ipv6_get_version(const ipv6_hdr_t *hdr);
uint8_t ipv6_get_traffic_class(const ipv6_hdr_t *hdr);
uint32_t ipv6_get_flow_label(const ipv6_hdr_t *hdr);
void ipv6_set_version_tc_flow(ipv6_hdr_t *hdr, uint8_t version, uint8_t tc, uint32_t flow);

#endif
