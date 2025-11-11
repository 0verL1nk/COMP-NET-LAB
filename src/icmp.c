#include "icmp.h"

#include "ip.h"
#include "net.h"

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
    // 检查该ICMP报文的类型是否为回显请求
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step3: 回送回显应答
        // 如果该报文的ICMP类型是回显请求，则调用icmp_resp()函数回送一个回显应答
        icmp_resp(buf, src_ip);
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
}
