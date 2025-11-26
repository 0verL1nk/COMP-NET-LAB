# ICMP Ping 实验报告

## 设计方案

### 整体思路
本次实验实现了类似PING工具的功能，能够主动发起ICMP请求并监听回复。整体设计遵循了原有协议栈的架构模式，在ICMP模块基础上扩展了ping功能。

### 数据结构设计

1. **ICMP Ping请求结构体 (`icmp_ping_request_t`)**
   ```c
   typedef struct icmp_ping_request {
       uint16_t id;          // 请求ID
       uint16_t seq;         // 序列号
       time_t timestamp;     // 发送时间戳
       uint8_t dest_ip[NET_IP_LEN];  // 目标IP
   } icmp_ping_request_t;
   ```

2. **统计信息结构体 (`icmp_ping_stats_t`)**
   ```c
   typedef struct icmp_ping_stats {
       int sent;             // 发送请求数
       int received;         // 收到回复数
       long min_time;        // 最小响应时间(ms)
       long max_time;        // 最大响应时间(ms)
       long total_time;      // 总响应时间
   } icmp_ping_stats_t;
   ```

3. **请求映射表**
   使用协议栈自带的`map_t`数据结构存储待处理的ping请求，设置5秒超时时间。

### 函数功能划分

#### ICMP模块扩展
1. `icmp_ping_request()` - 构造并发送ICMP Echo请求
2. `icmp_ping_report_stats()` - 报告统计信息
3. `icmp_get_pending_requests_count()` - 获取待处理请求数量
4. 增强`icmp_in()`函数以处理ICMP Echo回复

#### Ping应用主程序 (`ping_app.c`)
1. 时间戳调度机制 - 每秒发送一次请求，共4次
2. 主循环处理 - 调用`net_poll()`处理网络事件
3. 统计结果显示 - 显示RTT和丢包率

## 实验结果

### 实现的功能
1. **ICMP Echo请求发送** - 每隔1秒自动发送一次请求，共发送4次
2. **响应处理** - 正确识别并处理ICMP Echo回复
3. **时间统计** - 记录每次请求的往返时间(RTT)
4. **超时管理** - 5秒后自动清理未响应的请求
5. **统计报告** - 显示详细的性能统计数据

### 输出格式示例
```
PING 192.168.1.1 (192.168.1.1): 56 data bytes
Sending ICMP echo request to 192.168.1.1, seq=0
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=5 ms
Sending ICMP echo request to 192.168.1.1, seq=1
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=3 ms
...

--- Ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max = 2/4.250/6 ms
```

## 分析

### 实现优势
1. **非阻塞设计** - 使用时间戳检查而非sleep，保证了主循环的实时性
2. **内存安全** - 利用现有的map数据结构自动管理超时和内存回收
3. **兼容性好** - 遵循现有代码风格和架构，易于集成
4. **功能完整** - 实现了标准ping工具的核心功能


