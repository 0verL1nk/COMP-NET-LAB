#ifndef CONFIG_H
#define CONFIG_H

#ifdef TEST
#define NET_IF_IP \
    {             \
        192, 168, 163, 103}  // 测试用网卡ip地址
#define NET_IF_MAC \
    {              \
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66}  // 测试用网卡mac地址
// 测试用IPv6地址 (链路本地地址，基于MAC地址生成)
#define NET_IF_IPV6 \
    {               \
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x13, 0x22, 0x33, 0xff, 0xfe, 0x44, 0x55, 0x66}
#else
#define NET_IF_IP \
    {             \
        172, 17, 95, 24}  // 自定义网卡ip地址
#define NET_IF_MAC \
    {              \
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55}  // 自定义网卡mac地址
// 自定义IPv6地址 (链路本地地址，基于MAC地址生成)
#define NET_IF_IPV6 \
    {               \
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}
#endif

#define ETHERNET_MAX_TRANSPORT_UNIT 1500  // 以太网最大传输单元

#define ARP_TIMEOUT_SEC (60 * 5)  // arp表过期时间
#define ARP_MIN_INTERVAL 1        // 向相同地址发送arp请求的最小间隔

#define IP_DEFALUT_TTL 64  // IP默认TTL

#define BUF_MAX_LEN (2 * UINT16_MAX + UINT8_MAX)  // buf最大长度

#define MAP_MAX_LEN (16 * BUF_MAX_LEN)  // map最大长度
#endif