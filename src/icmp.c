#include "icmp.h"

#include "ip.h"
#include "net.h"
#include <stdio.h>
#include <time.h>

// Global variables for ping functionality
static map_t icmp_ping_requests;     // Map to store pending ping requests
static icmp_ping_stats_t icmp_stats; // Statistics for ping requests
static uint16_t icmp_ping_id = 0;    // ID for ping requests

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化并封装数据
    // 创建一个新的缓冲区来存储响应
    buf_init(&txbuf, req_buf->len);
    
    // 复制请求数据到响应缓冲区
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    
    // 获取响应包的ICMP头部指针
    icmp_hdr_t *resp_hdr = (icmp_hdr_t *)txbuf.data;
    
    // 修改类型为回显应答，保持其他字段不变
    resp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    
    // Step2: 填写校验和
    resp_hdr->checksum16 = 0;  // 先将校验和字段置0
    
    // 计算校验和，正确处理奇数长度
    if (txbuf.len % 2 == 1) {
        // 如果长度为奇数，需要特殊处理最后一个字节
        uint16_t *data = (uint16_t *)resp_hdr;
        uint32_t sum = 0;
        
        // 处理完整的16位字
        for (int i = 0; i < txbuf.len / 2; i++) {
            sum += data[i];
        }
        
        // 处理最后一个字节（作为16位值的低8位，高8位为0）
        sum += ((uint8_t *)resp_hdr)[txbuf.len - 1];
        
        // 处理进位
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        resp_hdr->checksum16 = ~sum;
    } else {
        resp_hdr->checksum16 = checksum16((uint16_t *)resp_hdr, txbuf.len / 2);
    }
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);  // 通过IP层发送响应
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 报头检测
    // 检查接收到的数据包长度是否小于ICMP头部长度
    if (buf->len < sizeof(icmp_hdr_t)) {
        return; // 数据包不完整，丢弃
    }

    // 获取ICMP头部指针
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;

    // Step2: 查看ICMP类型
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // 回显请求 - 回送回显应答
        icmp_resp(buf, src_ip);
    } else if (hdr->type == ICMP_TYPE_ECHO_REPLY) {
        // 回显应答 - handle ping reply
        uint16_t seq = hdr->seq16;

        // Look up the request in our map
        icmp_ping_request_t *request = map_get(&icmp_ping_requests, &seq);
        if (request != NULL) {
            // Calculate response time
            time_t now = time(NULL);
            long response_time = (now - request->timestamp) * 1000; // Convert to milliseconds

            // Print reply information in ping format
            printf("%ld bytes from %s: icmp_seq=%d ttl=64 time=%ld ms\n",
                   (long)buf->len, iptos(src_ip), seq, response_time);

            // Update statistics
            icmp_stats.received++;
            icmp_stats.total_time += response_time;

            // Update min/max times
            if (icmp_stats.received == 1 || response_time < icmp_stats.min_time) {
                icmp_stats.min_time = response_time;
            }
            if (response_time > icmp_stats.max_time) {
                icmp_stats.max_time = response_time;
            }

            // Remove the request from the map as it's been handled
            map_delete(&icmp_ping_requests, &seq);
        }
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化并填写报头
    // 计算ICMP不可达报文的大小：ICMP头部 + IP头部 + 原始IP数据报的前8个字节
    ip_hdr_t *orig_hdr = (ip_hdr_t *)recv_buf->data;
    uint8_t ip_hdr_len = orig_hdr->hdr_len * 4;  // IP头部长度（以字节为单位）
    // 确保至少复制IP头部和原始数据包的前8字节（或者如果数据包长度不足8字节，则复制全部数据）
    int data_to_copy = 8;
    if (recv_buf->len < ip_hdr_len + 8) {
        data_to_copy = recv_buf->len - ip_hdr_len;
    }
    int icmp_data_len = ip_hdr_len + data_to_copy; // IP头部 + 数据部分
    int total_len = sizeof(icmp_hdr_t) + icmp_data_len;  // ICMP头部 + 数据部分
    
    // 初始化txbuf
    buf_init(&txbuf, total_len);
    
    // 获取ICMP头部指针
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    
    // 填写ICMP头部
    icmp_hdr->type = ICMP_TYPE_UNREACH;  // 类型为不可达
    icmp_hdr->code = code;               // 代码为传入的参数
    icmp_hdr->checksum16 = 0;            // 校验和先置0
    icmp_hdr->id16 = 0;                  // ID字段
    icmp_hdr->seq16 = 0;                 // 序号字段
    
    // Step2: 填写数据与校验和
    // 复制原始IP头部和前8字节数据到ICMP数据部分
    uint8_t *icmp_data = txbuf.data + sizeof(icmp_hdr_t);
    memcpy(icmp_data, recv_buf->data, icmp_data_len);
    
    // 计算校验和
    icmp_hdr->checksum16 = 0;  // 先将校验和字段置0
    
    // 计算校验和，正确处理奇数长度
    if (txbuf.len % 2 == 1) {
        // 如果长度为奇数，需要特殊处理最后一个字节
        uint16_t *data = (uint16_t *)txbuf.data;
        uint32_t sum = 0;
        
        // 处理完整的16位字
        for (int i = 0; i < txbuf.len / 2; i++) {
            sum += data[i];
        }
        
        // 处理最后一个字节（作为16位值的高8位，低8位为0）
        sum += ((uint8_t *)txbuf.data)[txbuf.len - 1] << 8;
        
        // 处理进位
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        icmp_hdr->checksum16 = ~sum;
    } else {
        icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len / 2);
    }
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);  // 通过IP层发送响应
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
    // Initialize ping request map with 5 second timeout
    map_init(&icmp_ping_requests, sizeof(uint16_t), sizeof(icmp_ping_request_t), 0, 5, NULL, NULL);
    // Initialize statistics
    icmp_stats.sent = 0;
    icmp_stats.received = 0;
    icmp_stats.min_time = 0;
    icmp_stats.max_time = 0;
    icmp_stats.total_time = 0;
}

/**
 * @brief 发送ICMP ping请求
 *
 * @param dest_ip 目标IP地址
 */
void icmp_ping_request(uint8_t *dest_ip) {
    // Create ICMP echo request packet
    buf_init(&txbuf, 56); // Standard ping payload size

    // Fill payload with some data (optional)
    for (int i = 0; i < txbuf.len; i++) {
        txbuf.data[i] = (uint8_t)(i % 256);
    }

    // Add ICMP header
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;

    // Fill ICMP header fields
    icmp_hdr->type = ICMP_TYPE_ECHO_REQUEST;
    icmp_hdr->code = 0;
    icmp_hdr->id16 = icmp_ping_id;
    icmp_hdr->seq16 = icmp_stats.sent; // Use sent count as sequence number
    icmp_hdr->checksum16 = 0; // Will calculate later

    // Calculate checksum
    icmp_hdr->checksum16 = 0; // Reset checksum

    // Calculate checksum, correctly handling odd lengths
    if (txbuf.len % 2 == 1) {
        // If length is odd, special handling for last byte
        uint16_t *data = (uint16_t *)icmp_hdr;
        uint32_t sum = 0;

        // Process complete 16-bit words
        for (int i = 0; i < txbuf.len / 2; i++) {
            sum += data[i];
        }

        // Handle last byte (as low 8 bits of 16-bit value, high 8 bits = 0)
        sum += ((uint8_t *)icmp_hdr)[txbuf.len - 1];

        // Handle carry
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        icmp_hdr->checksum16 = ~sum;
    } else {
        icmp_hdr->checksum16 = checksum16((uint16_t *)icmp_hdr, txbuf.len / 2);
    }

    // Store request information for tracking replies
    icmp_ping_request_t request;
    request.id = icmp_ping_id;
    request.seq = icmp_stats.sent;
    request.timestamp = time(NULL);
    memcpy(request.dest_ip, dest_ip, NET_IP_LEN);

    // Store in map using sequence number as key
    map_set(&icmp_ping_requests, &request.seq, &request);

    // Send the packet via IP layer
    ip_out(&txbuf, dest_ip, NET_PROTOCOL_ICMP);

    // Update statistics
    icmp_stats.sent++;
    icmp_ping_id++; // Increment ID for next request

    // Print sending message
    printf("Sending ICMP echo request to %s, seq=%d\n", iptos(dest_ip), request.seq);
}

/**
 * @brief Report ping statistics
 */
void icmp_ping_report_stats() {
    printf("\n--- Ping statistics ---\n");
    printf("%d packets transmitted, %d received, ", icmp_stats.sent, icmp_stats.received);

    if (icmp_stats.sent > 0) {
        int loss_percent = (icmp_stats.sent - icmp_stats.received) * 100 / icmp_stats.sent;
        printf("%d%% packet loss\n", loss_percent);
    } else {
        printf("0%% packet loss\n");
    }

    if (icmp_stats.received > 0) {
        double avg_time = (double)icmp_stats.total_time / icmp_stats.received;
        printf("rtt min/avg/max = %ld/%.3f/%ld ms\n",
               icmp_stats.min_time, avg_time, icmp_stats.max_time);
    }
}

/**
 * @brief Get count of pending ping requests
 */
int icmp_get_pending_requests_count() {
    return map_size(&icmp_ping_requests);
}
