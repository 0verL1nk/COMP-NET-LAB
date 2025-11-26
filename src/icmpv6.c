#include "icmpv6.h"
#include "ipv6.h"
#include "net.h"
#include "ethernet.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief 计算ICMPv6校验和
 * 
 * ICMPv6校验和计算需要包含IPv6伪头部
 * 
 * @param buf ICMPv6消息缓冲区
 * @param src_ip 源IPv6地址
 * @param dst_ip 目标IPv6地址
 * @return uint16_t 校验和（网络字节序）
 */
uint16_t icmpv6_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
    uint32_t sum = 0;
    
    // 1. 计算伪头部的校验和
    // 源地址 (按16位字处理，直接用网络字节序)
    for (int i = 0; i < NET_IPV6_LEN; i += 2) {
        sum += (src_ip[i] << 8) | src_ip[i + 1];
    }
    
    // 目标地址
    for (int i = 0; i < NET_IPV6_LEN; i += 2) {
        sum += (dst_ip[i] << 8) | dst_ip[i + 1];
    }
    
    // 上层协议长度（32位，网络字节序）
    sum += (buf->len >> 16) & 0xFFFF;
    sum += buf->len & 0xFFFF;
    
    // 下一头部(58 = ICMPv6) - 32位字段中只有最后一个字节有值
    sum += 58;
    
    // 2. 计算ICMPv6消息体的校验和
    uint8_t *data = buf->data;
    int len = buf->len;
    
    while (len > 1) {
        sum += (data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    
    // 如果长度为奇数，处理最后一个字节
    if (len == 1) {
        sum += data[0] << 8;
    }
    
    // 折叠32位和为16位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // 返回反码，并转换为网络字节序
    uint16_t result = ~sum & 0xFFFF;
    return swap16(result);
}

/**
 * @brief 发送ICMPv6 Echo响应
 */
static void icmpv6_echo_reply(buf_t *req_buf, uint8_t *src_ip) {
    // 初始化响应缓冲区
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    
    // 修改类型为回显响应
    icmpv6_echo_t *echo = (icmpv6_echo_t *)txbuf.data;
    echo->type = ICMPV6_TYPE_ECHO_REPLY;
    echo->code = 0;
    
    // 计算校验和
    echo->checksum16 = 0;
    echo->checksum16 = icmpv6_checksum(&txbuf, net_if_ipv6, src_ip);
    
    // 发送响应
    ipv6_out(&txbuf, src_ip, IPV6_NEXT_HEADER_ICMPV6);
}

/**
 * @brief 处理邻居请求 (Neighbor Solicitation)
 */
static void icmpv6_handle_ns(buf_t *buf, uint8_t *src_ip) {
    if (buf->len < sizeof(icmpv6_ns_t)) {
        return;
    }
    
    icmpv6_ns_t *ns = (icmpv6_ns_t *)buf->data;
    
    // 检查目标地址是否是本机地址
    if (!ipv6_addr_equal(ns->target_ip, net_if_ipv6)) {
        return;  // 不是请求本机的地址，忽略
    }
    
    // 发送邻居通告
    icmpv6_send_na(ns->target_ip, src_ip, 1);
}

/**
 * @brief 处理邻居通告 (Neighbor Advertisement)
 */
static void icmpv6_handle_na(buf_t *buf, uint8_t *src_ip) {
    if (buf->len < sizeof(icmpv6_na_t)) {
        return;
    }
    
    icmpv6_na_t *na = (icmpv6_na_t *)buf->data;
    
    // 提取目标链路层地址选项
    if (buf->len >= sizeof(icmpv6_na_t) + sizeof(ndp_option_lla_t)) {
        ndp_option_lla_t *lla = (ndp_option_lla_t *)(buf->data + sizeof(icmpv6_na_t));
        if (lla->type == NDP_OPTION_TARGET_LLA && lla->length == 1) {
            // 可以在这里更新邻居缓存
            printf("ICMPv6: Received NA from %s, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   ipv6_to_str(src_ip),
                   lla->mac[0], lla->mac[1], lla->mac[2],
                   lla->mac[3], lla->mac[4], lla->mac[5]);
        }
    }
}

/**
 * @brief 处理收到的ICMPv6数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源IPv6地址
 */
void icmpv6_in(buf_t *buf, uint8_t *src_ip) {
    // 检查数据包长度
    if (buf->len < sizeof(icmpv6_hdr_t)) {
        return;
    }
    
    icmpv6_hdr_t *hdr = (icmpv6_hdr_t *)buf->data;
    
    // 验证校验和
    uint16_t old_checksum = hdr->checksum16;
    hdr->checksum16 = 0;
    uint16_t calc_checksum = icmpv6_checksum(buf, src_ip, net_if_ipv6);
    
    if (calc_checksum != old_checksum) {
        hdr->checksum16 = old_checksum;
        printf("ICMPv6: Checksum error (expected %04x, got %04x)\n", 
               old_checksum, calc_checksum);
        return;
    }
    hdr->checksum16 = old_checksum;
    
    // 根据类型处理
    switch (hdr->type) {
        case ICMPV6_TYPE_ECHO_REQUEST:
            printf("ICMPv6: Received Echo Request from %s\n", ipv6_to_str(src_ip));
            icmpv6_echo_reply(buf, src_ip);
            break;
            
        case ICMPV6_TYPE_ECHO_REPLY:
            printf("ICMPv6: Received Echo Reply from %s\n", ipv6_to_str(src_ip));
            // 可以在这里处理ping响应
            break;
            
        case ICMPV6_TYPE_NS:
            printf("ICMPv6: Received Neighbor Solicitation from %s\n", ipv6_to_str(src_ip));
            icmpv6_handle_ns(buf, src_ip);
            break;
            
        case ICMPV6_TYPE_NA:
            printf("ICMPv6: Received Neighbor Advertisement from %s\n", ipv6_to_str(src_ip));
            icmpv6_handle_na(buf, src_ip);
            break;
            
        case ICMPV6_TYPE_RS:
            printf("ICMPv6: Received Router Solicitation from %s\n", ipv6_to_str(src_ip));
            // 路由器请求处理（本实现不作为路由器）
            break;
            
        case ICMPV6_TYPE_RA:
            printf("ICMPv6: Received Router Advertisement from %s\n", ipv6_to_str(src_ip));
            // 路由器通告处理
            break;
            
        default:
            printf("ICMPv6: Received unknown type %d from %s\n", hdr->type, ipv6_to_str(src_ip));
            break;
    }
}

/**
 * @brief 发送ICMPv6不可达消息
 */
void icmpv6_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmpv6_dest_unreach_code_t code) {
    // ICMPv6不可达消息格式：
    // Type(1) + Code(1) + Checksum(2) + Unused(4) + 原始数据包（尽可能多，但总长度不超过MTU）
    
    int max_orig_len = 1280 - IPV6_HDR_LEN - 8;  // IPv6最小MTU - IPv6头 - ICMPv6头
    int orig_len = recv_buf->len < max_orig_len ? recv_buf->len : max_orig_len;
    int total_len = 8 + orig_len;  // ICMPv6头部(8) + 原始数据
    
    buf_init(&txbuf, total_len);
    
    // 填写ICMPv6头部
    icmpv6_hdr_t *hdr = (icmpv6_hdr_t *)txbuf.data;
    hdr->type = ICMPV6_TYPE_DEST_UNREACH;
    hdr->code = code;
    hdr->checksum16 = 0;
    
    // 4字节未使用字段
    memset(txbuf.data + 4, 0, 4);
    
    // 复制原始数据包
    memcpy(txbuf.data + 8, recv_buf->data, orig_len);
    
    // 计算校验和
    hdr->checksum16 = icmpv6_checksum(&txbuf, net_if_ipv6, src_ip);
    
    // 发送
    ipv6_out(&txbuf, src_ip, IPV6_NEXT_HEADER_ICMPV6);
}

/**
 * @brief 发送ICMPv6 Echo请求 (ping6)
 */
void icmpv6_echo_request(uint8_t *dest_ip, uint16_t id, uint16_t seq, uint8_t *data, uint16_t data_len) {
    int total_len = sizeof(icmpv6_echo_t) + data_len;
    
    buf_init(&txbuf, total_len);
    
    icmpv6_echo_t *echo = (icmpv6_echo_t *)txbuf.data;
    echo->type = ICMPV6_TYPE_ECHO_REQUEST;
    echo->code = 0;
    echo->checksum16 = 0;
    echo->id16 = swap16(id);
    echo->seq16 = swap16(seq);
    
    // 复制数据
    if (data && data_len > 0) {
        memcpy(txbuf.data + sizeof(icmpv6_echo_t), data, data_len);
    }
    
    // 计算校验和
    echo->checksum16 = icmpv6_checksum(&txbuf, net_if_ipv6, dest_ip);
    
    // 发送
    ipv6_out(&txbuf, dest_ip, IPV6_NEXT_HEADER_ICMPV6);
    
    printf("ICMPv6: Sent Echo Request to %s, id=%d, seq=%d\n", 
           ipv6_to_str(dest_ip), id, seq);
}

/**
 * @brief 发送邻居请求 (Neighbor Solicitation)
 */
void icmpv6_send_ns(uint8_t *target_ip) {
    int total_len = sizeof(icmpv6_ns_t) + sizeof(ndp_option_lla_t);
    
    buf_init(&txbuf, total_len);
    
    icmpv6_ns_t *ns = (icmpv6_ns_t *)txbuf.data;
    ns->type = ICMPV6_TYPE_NS;
    ns->code = 0;
    ns->checksum16 = 0;
    ns->reserved = 0;
    memcpy(ns->target_ip, target_ip, NET_IPV6_LEN);
    
    // 添加源链路层地址选项
    ndp_option_lla_t *lla = (ndp_option_lla_t *)(txbuf.data + sizeof(icmpv6_ns_t));
    lla->type = NDP_OPTION_SOURCE_LLA;
    lla->length = 1;  // 8字节单位
    memcpy(lla->mac, net_if_mac, NET_MAC_LEN);
    
    // 构造请求节点组播地址 ff02::1:ffxx:xxxx
    uint8_t solicited_node_multicast[NET_IPV6_LEN] = {
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0xff, target_ip[13], target_ip[14], target_ip[15]
    };
    
    // 计算校验和
    ns->checksum16 = icmpv6_checksum(&txbuf, net_if_ipv6, solicited_node_multicast);
    
    // 发送到请求节点组播地址
    ipv6_out(&txbuf, solicited_node_multicast, IPV6_NEXT_HEADER_ICMPV6);
    
    printf("ICMPv6: Sent Neighbor Solicitation for %s\n", ipv6_to_str(target_ip));
}

/**
 * @brief 发送邻居通告 (Neighbor Advertisement)
 */
void icmpv6_send_na(uint8_t *target_ip, uint8_t *dest_ip, int solicited) {
    int total_len = sizeof(icmpv6_na_t) + sizeof(ndp_option_lla_t);
    
    buf_init(&txbuf, total_len);
    
    icmpv6_na_t *na = (icmpv6_na_t *)txbuf.data;
    na->type = ICMPV6_TYPE_NA;
    na->code = 0;
    na->checksum16 = 0;
    
    // 设置标志
    uint32_t flags = ICMPV6_NA_FLAG_OVERRIDE;  // O标志
    if (solicited) {
        flags |= ICMPV6_NA_FLAG_SOLICITED;     // S标志
    }
    na->flags = swap32(flags);
    
    memcpy(na->target_ip, target_ip, NET_IPV6_LEN);
    
    // 添加目标链路层地址选项
    ndp_option_lla_t *lla = (ndp_option_lla_t *)(txbuf.data + sizeof(icmpv6_na_t));
    lla->type = NDP_OPTION_TARGET_LLA;
    lla->length = 1;  // 8字节单位
    memcpy(lla->mac, net_if_mac, NET_MAC_LEN);
    
    // 计算校验和
    na->checksum16 = icmpv6_checksum(&txbuf, net_if_ipv6, dest_ip);
    
    // 发送
    ipv6_out(&txbuf, dest_ip, IPV6_NEXT_HEADER_ICMPV6);
    
    printf("ICMPv6: Sent Neighbor Advertisement to %s\n", ipv6_to_str(dest_ip));
}

/**
 * @brief 初始化ICMPv6协议
 */
void icmpv6_init() {
    printf("ICMPv6 initialized\n");
}
