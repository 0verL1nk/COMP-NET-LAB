#ifndef ICMPV6_H
#define ICMPV6_H

#include "net.h"
#include "ipv6.h"

#pragma pack(1)
/**
 * @brief ICMPv6 头部结构
 */
typedef struct icmpv6_hdr {
    uint8_t type;           // 类型
    uint8_t code;           // 代码
    uint16_t checksum16;    // 校验和
} icmpv6_hdr_t;

/**
 * @brief ICMPv6 Echo请求/响应消息
 */
typedef struct icmpv6_echo {
    uint8_t type;           // 类型 (128=请求, 129=响应)
    uint8_t code;           // 代码 (必须为0)
    uint16_t checksum16;    // 校验和
    uint16_t id16;          // 标识符
    uint16_t seq16;         // 序列号
    // 后面跟着可选的数据
} icmpv6_echo_t;

/**
 * @brief 邻居请求消息 (Neighbor Solicitation)
 */
typedef struct icmpv6_ns {
    uint8_t type;           // 类型 (135)
    uint8_t code;           // 代码 (必须为0)
    uint16_t checksum16;    // 校验和
    uint32_t reserved;      // 保留字段
    uint8_t target_ip[NET_IPV6_LEN]; // 目标地址
    // 后面可以跟选项 (如源链路层地址选项)
} icmpv6_ns_t;

/**
 * @brief 邻居通告消息 (Neighbor Advertisement)
 */
typedef struct icmpv6_na {
    uint8_t type;           // 类型 (136)
    uint8_t code;           // 代码 (必须为0)
    uint16_t checksum16;    // 校验和
    uint32_t flags;         // R(路由器)、S(请求响应)、O(覆盖)标志 + 保留位
    uint8_t target_ip[NET_IPV6_LEN]; // 目标地址
    // 后面可以跟选项 (如目标链路层地址选项)
} icmpv6_na_t;

/**
 * @brief NDP选项：链路层地址
 */
typedef struct ndp_option_lla {
    uint8_t type;           // 类型 (1=源链路层地址, 2=目标链路层地址)
    uint8_t length;         // 长度 (以8字节为单位)
    uint8_t mac[NET_MAC_LEN]; // MAC地址
} ndp_option_lla_t;

/**
 * @brief ICMPv6 伪头部（用于计算校验和）
 */
typedef struct icmpv6_pseudo_hdr {
    uint8_t src_ip[NET_IPV6_LEN];   // 源IPv6地址
    uint8_t dst_ip[NET_IPV6_LEN];   // 目标IPv6地址
    uint32_t upper_len;             // ICMPv6长度（网络字节序）
    uint8_t zeros[3];               // 零填充
    uint8_t next_header;            // 下一头部 = 58
} icmpv6_pseudo_hdr_t;
#pragma pack()

// ICMPv6 消息类型定义
typedef enum icmpv6_type {
    // 错误消息 (0-127)
    ICMPV6_TYPE_DEST_UNREACH = 1,       // 目标不可达
    ICMPV6_TYPE_PKT_TOO_BIG = 2,        // 包太大
    ICMPV6_TYPE_TIME_EXCEEDED = 3,      // 超时
    ICMPV6_TYPE_PARAM_PROBLEM = 4,      // 参数问题
    
    // 信息消息 (128-255)
    ICMPV6_TYPE_ECHO_REQUEST = 128,     // 回显请求
    ICMPV6_TYPE_ECHO_REPLY = 129,       // 回显响应
    
    // 邻居发现协议消息
    ICMPV6_TYPE_RS = 133,               // 路由器请求
    ICMPV6_TYPE_RA = 134,               // 路由器通告
    ICMPV6_TYPE_NS = 135,               // 邻居请求
    ICMPV6_TYPE_NA = 136,               // 邻居通告
    ICMPV6_TYPE_REDIRECT = 137,         // 重定向
} icmpv6_type_t;

// ICMPv6 目标不可达代码
typedef enum icmpv6_dest_unreach_code {
    ICMPV6_CODE_NO_ROUTE = 0,           // 无路由到达目标
    ICMPV6_CODE_ADMIN_PROHIBITED = 1,   // 管理禁止
    ICMPV6_CODE_BEYOND_SCOPE = 2,       // 超出源地址范围
    ICMPV6_CODE_ADDR_UNREACH = 3,       // 地址不可达
    ICMPV6_CODE_PORT_UNREACH = 4,       // 端口不可达
} icmpv6_dest_unreach_code_t;

// NDP选项类型
typedef enum ndp_option_type {
    NDP_OPTION_SOURCE_LLA = 1,          // 源链路层地址
    NDP_OPTION_TARGET_LLA = 2,          // 目标链路层地址
    NDP_OPTION_PREFIX_INFO = 3,         // 前缀信息
    NDP_OPTION_REDIRECT_HDR = 4,        // 重定向头部
    NDP_OPTION_MTU = 5,                 // MTU
} ndp_option_type_t;

// NA标志位定义
#define ICMPV6_NA_FLAG_ROUTER    0x80000000  // R标志：发送者是路由器
#define ICMPV6_NA_FLAG_SOLICITED 0x40000000  // S标志：响应NS请求
#define ICMPV6_NA_FLAG_OVERRIDE  0x20000000  // O标志：覆盖已有缓存条目

// 函数声明
void icmpv6_init();
void icmpv6_in(buf_t *buf, uint8_t *src_ip);
void icmpv6_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmpv6_dest_unreach_code_t code);
void icmpv6_echo_request(uint8_t *dest_ip, uint16_t id, uint16_t seq, uint8_t *data, uint16_t data_len);

// 邻居发现协议函数
void icmpv6_send_ns(uint8_t *target_ip);
void icmpv6_send_na(uint8_t *target_ip, uint8_t *dest_ip, int solicited);

// 校验和计算
uint16_t icmpv6_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip);

#endif
