#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {  // IP头部最小长度是20字节
        return;           // 数据包不完整，丢弃
    }

    // 获取IP头部
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

    // Step2: 进行报头检测
    // 检查版本号是否为IPv4
    if (hdr->version != IP_VERSION_4) {
        return;  // 版本号不正确，丢弃
    }

    // 计算IP头部长度（以字节为单位）
    uint8_t ip_hdr_len = hdr->hdr_len * IP_HDR_LEN_PER_BYTE;  // hdr_len以4字节为单位，需要乘以4得到实际字节数
    if (ip_hdr_len < sizeof(ip_hdr_t)) {                  // IP头部最小长度是20字节
        return;                             // IP头部长度小于最小值，丢弃
    }

    // 检查总长度字段是否小于或等于收到的数据包长度
    uint16_t total_len = swap16(hdr->total_len16);
    if (total_len > buf->len || total_len < ip_hdr_len) {
        return; // 总长度超过数据包长度或小于头部长度，丢弃
    }

    // Step3: 校验头部校验和
    uint16_t old_checksum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;  // 将校验和字段置为0
    uint16_t calculated_checksum = checksum16((uint16_t *)hdr, ip_hdr_len / 2);

    if (calculated_checksum != old_checksum) {
        hdr->hdr_checksum16 = old_checksum;  // 恢复原始校验和值
        return;                              // 校验和不一致，丢弃
    }
    hdr->hdr_checksum16 = old_checksum;  // 恢复原始校验和值

    // 对比目的IP地址
    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;  // 目的IP不是本机IP，丢弃
    }

    // 去除填充字段
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }

    // 去掉IP报头
    buf_remove_header(buf, ip_hdr_len);

    // 向上层传递数据包，传递源IP地址而不是源MAC地址
    int result = net_in(buf, (uint16_t)hdr->protocol, hdr->src_ip);
    if (result < 0) {
        // 如果遇到不能识别的协议类型，调用icmp_unreachable返回ICMP协议不可达信息
        // 需要先重新加入IP报头
        buf_add_header(buf, ip_hdr_len);
        hdr = (ip_hdr_t *)buf->data;  // 重新获取IP头部指针
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // Step1: 增加头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    
    // Step2: 填写头部字段
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    
    hdr->version = IP_VERSION_4;        // 版本号为IPv4
    hdr->hdr_len = 5;                   // 首部长度为5个4字节单位（20字节）
    hdr->tos = 0;                       // 区分服务字段为0
    hdr->total_len16 = swap16(buf->len); // 总长度，转换为网络字节序
    hdr->id16 = swap16(id);             // 数据包ID，转换为网络字节序
    hdr->ttl = 64;                      // TTL值设为64
    hdr->protocol = protocol;           // 上层协议
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);  // 源IP地址
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);         // 目标IP地址
    
    // 设置分片相关字段
    uint16_t flags_fragment = 0;
    if (mf) {
        flags_fragment |= IP_MORE_FRAGMENT;  // 设置MF标志
    }
    flags_fragment |= (offset & 0x1FFF);     // 设置分片偏移，只取低13位
    hdr->flags_fragment16 = swap16(flags_fragment);  // 转换为网络字节序
    
    // 计算并填写校验和
    hdr->hdr_checksum16 = 0;  // 先将校验和字段填为0
    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t) / 2);  // 计算校验和并填入字段
    
    arp_out(buf, ip);  
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    const uint16_t MTU = 1500;
    uint8_t ip_hdr_len = 20; // 基本IP头部长度为20字节

    // 检查数据报包长
    uint16_t max_payload = MTU - ip_hdr_len;
    if (buf->len > max_payload) {
        // 分片处理
        // 静态ID计数器，用于标识同一数据报的不同分片
        static int id = 0;
        int current_id = id; // 使用当前ID发送所有分片
        
        int offset = 0; // 当前偏移量（以字节为单位）
        int remaining = buf->len; // 剩余待发送字节数
        
        while (remaining > 0) {
            // 计算当前分片的数据长度
            int frag_size = (remaining > max_payload) ? max_payload : remaining;
            
            // 创建分片数据包
            buf_t ip_buf;
            buf_init(&ip_buf, frag_size);
            memcpy(ip_buf.data, buf->data + offset, frag_size);
            
            // 计算偏移量（以8字节为单位）
            uint16_t frag_offset = offset / 8;
            
            // 判断是否是最后一个分片
            int mf = (remaining > max_payload) ? 1 : 0;
            
            // 调用ip_fragment_out发送分片
            ip_fragment_out(&ip_buf, ip, protocol, current_id, frag_offset, mf);
            
            // 更新偏移量和剩余字节数
            offset += frag_size;
            remaining -= frag_size;
        }
        
        // ID递增，用于下一个数据报
        id++;
    } else {
        // 直接发送
        static int id = 0;
        // 直接调用ip_fragment_out发送，偏移量为0，MF标志为0（单个分片）
        ip_fragment_out(buf, ip, protocol, id++, 0, 0);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
