#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    buf_init(&txbuf, 0);
    // arp head
    buf_add_header(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *arp_hdr = (arp_pkt_t *)txbuf.data;
    memcpy(arp_hdr, &arp_init_pkt, sizeof(arp_pkt_t));
    arp_hdr->opcode16 = swap16(ARP_REQUEST);
    memcpy(arp_hdr->target_ip, target_ip, NET_IP_LEN);
    // ethernet
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // init buf
    buf_init(&txbuf, 0);
    // init header
    buf_add_header(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *arp_hdr = (arp_pkt_t *)txbuf.data;
    memcpy(arp_hdr, &arp_init_pkt, sizeof(arp_pkt_t));
    // 设置ARP响应的字段
    arp_hdr->opcode16 = swap16(ARP_REPLY);
    memcpy(arp_hdr->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_hdr->target_mac, target_mac, NET_MAC_LEN);
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP); 
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // check head
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }
    // head more check
    arp_pkt_t *arp_hdr = (arp_pkt_t *)buf->data;

    if (swap16(arp_hdr->hw_type16) != ARP_HW_ETHER ||
        swap16(arp_hdr->pro_type16) != NET_PROTOCOL_IP ||
        arp_hdr->hw_len != NET_MAC_LEN ||
        arp_hdr->pro_len != NET_IP_LEN) {
        return;
    }
    // update arp table
    map_set(&arp_table, arp_hdr->sender_ip, arp_hdr->sender_mac);
    // if have buf, send it
    if (map_get(&arp_buf, arp_hdr->sender_ip) != NULL) {
        buf_t *pending_buf = map_get(&arp_buf, arp_hdr->sender_ip);
        ethernet_out(pending_buf, arp_hdr->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_hdr->sender_ip);
    } else {
        // check if a REQUEST for mac
        if (swap16(arp_hdr->opcode16) == ARP_REQUEST && arp_hdr->target_ip[0] == net_if_ip[0] &&
            arp_hdr->target_ip[1] == net_if_ip[1] &&
            arp_hdr->target_ip[2] == net_if_ip[2] &&
            arp_hdr->target_ip[3] == net_if_ip[3]) {
            // send RESP
            arp_resp(arp_hdr->sender_ip, arp_hdr->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    void *res = map_get(&arp_table, ip);
    if (res != NULL) {
        // 找到mac地址，直接发送
        ethernet_out(buf, (uint8_t *)res, NET_PROTOCOL_IP);
    } else {
        if (map_get(&arp_buf, ip) != NULL) {
            // 有包,等待该ip回应,不能发送新的请求
            return;
        }
        // 没有包，缓存
        map_set(&arp_buf, ip, buf);
        // 发送arp请求
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}