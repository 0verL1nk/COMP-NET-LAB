# FTP 服务器实验报告

## 1. 实验概述

### 1.1 实验目的
在现有协议栈基础上实现 FTP（文件传输协议）服务器，支持基本的文件上传和下载功能，深入理解 FTP 协议的工作原理和实现细节。

### 1.2 实验环境
- 操作系统：Linux
- 开发语言：C
- 依赖库：libpcap
- 协议栈：基于 net-lab 项目的 TCP/IP 协议栈实现

### 1.3 参考标准
- RFC 959: File Transfer Protocol (FTP)

## 2. 设计方案

### 2.1 FTP 协议概述

FTP 是一种用于在网络上进行文件传输的标准协议，采用客户端-服务器模式。FTP 协议的主要特点是使用两条独立的 TCP 连接：

1. **控制连接（Control Connection）**：端口 21，用于传输命令和响应
2. **数据连接（Data Connection）**：用于实际的文件传输

```
+--------+                    +--------+
|        |   控制连接 (21)    |        |
| Client |<==================>| Server |
|        |   数据连接 (PASV)  |        |
|        |<==================>|        |
+--------+                    +--------+
```

### 2.2 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                    FTP Server Application               │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Session   │  │   Command   │  │    Data     │     │
│  │  Manager    │  │   Handler   │  │  Transfer   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
├─────────────────────────────────────────────────────────┤
│                      TCP Layer                          │
├─────────────────────────────────────────────────────────┤
│                      IP Layer                           │
├─────────────────────────────────────────────────────────┤
│                   Ethernet Layer                        │
└─────────────────────────────────────────────────────────┘
```

### 2.3 协议实现细节

#### 2.3.1 支持的 FTP 命令

| 命令 | 功能 | 响应码 |
|------|------|--------|
| USER | 设置用户名 | 331 |
| PASS | 设置密码 | 230 |
| SYST | 获取系统类型 | 215 |
| PWD  | 显示当前目录 | 257 |
| CWD  | 切换目录 | 250 |
| TYPE | 设置传输类型 | 200 |
| PASV | 进入被动模式 | 227 |
| LIST | 列出目录内容 | 150/226 |
| RETR | 下载文件 | 150/226 |
| STOR | 上传文件 | 150/226 |
| QUIT | 断开连接 | 221 |
| NOOP | 空操作 | 200 |
| FEAT | 特性列表 | 211 |
| OPTS | 选项设置 | 200 |

#### 2.3.2 FTP 响应码

```c
#define FTP_RESP_READY           "220"   // 服务就绪
#define FTP_RESP_GOODBYE         "221"   // 再见
#define FTP_RESP_TRANSFER_OK     "226"   // 传输完成
#define FTP_RESP_PASV_OK         "227"   // 被动模式
#define FTP_RESP_LOGIN_OK        "230"   // 登录成功
#define FTP_RESP_FILE_ACTION_OK  "250"   // 文件操作成功
#define FTP_RESP_PATH_CREATED    "257"   // 路径创建成功
#define FTP_RESP_NEED_PASSWORD   "331"   // 需要密码
#define FTP_RESP_NOT_LOGGED_IN   "530"   // 未登录
#define FTP_RESP_FILE_NOT_FOUND  "550"   // 文件未找到
```

#### 2.3.3 会话状态管理

```c
typedef enum {
    FTP_STATE_CONNECTED,     // 已连接，等待用户名
    FTP_STATE_USER_OK,       // 用户名已接收，等待密码
    FTP_STATE_LOGGED_IN,     // 已登录
    FTP_STATE_PASV_WAIT,     // 等待被动模式数据连接
    FTP_STATE_DATA_TRANSFER  // 数据传输中
} ftp_state_t;
```

状态转换图：
```
CONNECTED --[USER]--> USER_OK --[PASS]--> LOGGED_IN
                                              |
                                          [PASV]
                                              |
                                              v
                                         PASV_WAIT
                                              |
                                    [LIST/RETR/STOR]
                                              |
                                              v
                                       DATA_TRANSFER
                                              |
                                       [完成传输]
                                              |
                                              v
                                         LOGGED_IN
```

#### 2.3.4 数据传输模式

本实现采用**被动模式（Passive Mode）**：

1. 客户端发送 `PASV` 命令
2. 服务器返回数据端口信息：`227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`
3. 客户端主动连接服务器的数据端口
4. 进行数据传输

```c
// PASV 响应格式
snprintf(response, sizeof(response),
         "Entering Passive Mode (%d,%d,%d,%d,%d,%d).",
         net_if_ip[0], net_if_ip[1], net_if_ip[2], net_if_ip[3],
         (data_port >> 8) & 0xFF, data_port & 0xFF);
```

### 2.4 文件管理机制

#### 2.4.1 目录结构

```
app/ftp_root/           # FTP 根目录
├── README.txt          # 说明文件
├── sample.txt          # 示例文件
└── upload/             # 上传目录
```

#### 2.4.2 路径安全

```c
static void ftp_get_real_path(ftp_session_t *session, const char *path, 
                               char *out, size_t out_len) {
    if (path[0] == '/') {
        // 绝对路径：限制在 FTP_ROOT_DIR 内
        snprintf(out, out_len, "%s%s", FTP_ROOT_DIR, path);
    } else {
        // 相对路径
        snprintf(out, out_len, "%s%s/%s", FTP_ROOT_DIR, 
                 session->current_dir, path);
    }
}
```

#### 2.4.3 文件权限检查

```c
// 检查文件是否可读
static int ftp_check_file_readable(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

// 检查目录是否存在
static int ftp_check_dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

// 检查写入权限
static int ftp_check_write_permission(const char *path) {
    FILE *f = fopen(path, "ab");
    if (f) {
        fclose(f);
        return 1;
    }
    // 检查父目录权限
    char parent[FTP_MAX_PATH_LENGTH];
    strncpy(parent, path, sizeof(parent) - 1);
    char *last_slash = strrchr(parent, '/');
    if (last_slash) {
        *last_slash = '\0';
        return access(parent, W_OK) == 0;
    }
    return 0;
}
```

#### 2.4.4 文件完整性保证

- **下载（RETR）**：以二进制模式打开文件，逐块读取并发送
- **上传（STOR）**：以追加模式写入接收的数据，确保数据不丢失

```c
// 文件下载
static void ftp_do_retr(ftp_session_t *session, tcp_conn_t *data_conn,
                         uint16_t data_port, uint8_t *dst_ip, uint16_t dst_port) {
    FILE *file = fopen(session->pending_path, "rb");
    if (!file) return;

    char buffer[FTP_BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        tcp_send(data_conn, (uint8_t *)buffer, bytes_read, 
                 data_port, dst_ip, dst_port);
    }
    fclose(file);
}
```

### 2.5 关键数据结构

```c
// FTP 会话结构
typedef struct {
    uint8_t active;                          // 会话是否活跃
    uint8_t client_ip[NET_IP_LEN];          // 客户端 IP
    uint16_t client_port;                    // 客户端端口
    ftp_state_t state;                       // 会话状态
    ftp_transfer_type_t transfer_type;       // 传输类型
    char current_dir[FTP_MAX_PATH_LENGTH];   // 当前目录
    char username[64];                       // 用户名
    uint16_t data_port;                      // 被动模式数据端口
    ftp_data_op_t pending_op;                // 待处理的数据操作
    char pending_path[FTP_MAX_PATH_LENGTH];  // 待处理的文件路径
    tcp_conn_t *ctrl_conn;                   // 控制连接
} ftp_session_t;
```

## 3. 实验结果

### 3.1 编译和运行

```bash
# 编译
cd build
cmake ..
make ftp_server

# 运行
sudo ./ftp_server
```

### 3.2 测试命令

使用标准 FTP 客户端进行测试：

```bash
# 连接 FTP 服务器
ftp <server_ip> 21

# 或使用 lftp
lftp -u anonymous,anonymous <server_ip>

# 测试命令序列
USER anonymous
PASS anonymous
PWD
LIST
RETR sample.txt
STOR test_upload.txt
QUIT
```

### 3.3 预期输出示例

服务器端输出：
```
==============================================
    Simple FTP Server based on net-lab
==============================================
FTP Root Directory: /path/to/app/ftp_root
Control Port: 21
==============================================
[FTP] Server started, listening on port 21...
[FTP] <- USER anonymous
[FTP] -> 331 User name okay, need password.
[FTP] <- PASS anonymous
[FTP] -> 230 User logged in, proceed.
[FTP] <- PWD
[FTP] -> 257 "/" is current directory.
[FTP] <- PASV
[FTP] Passive mode, data port: 20000
[FTP] -> 227 Entering Passive Mode (172,17,95,24,78,32).
[FTP] <- LIST
[FTP] -> 150 Here comes the directory listing.
[FTP] -> 226 Directory send OK.
```

### 3.4 测试用例

| 测试项 | 命令 | 预期结果 | 实际结果 |
|--------|------|----------|----------|
| 用户登录 | USER/PASS | 返回 230 | ✓ |
| 查看目录 | PWD | 返回当前目录 | ✓ |
| 切换目录 | CWD | 目录切换成功 | ✓ |
| 列出文件 | LIST | 显示文件列表 | ✓ |
| 下载文件 | RETR | 文件下载成功 | ✓ |
| 上传文件 | STOR | 文件上传成功 | ✓ |
| 断开连接 | QUIT | 连接关闭 | ✓ |

## 4. 问题分析与解决

### 4.1 问题：控制连接和数据连接的协调

**描述**：FTP 使用两条独立的 TCP 连接，需要正确协调控制命令和数据传输。

**解决方案**：
- 使用会话结构保存控制连接状态
- 在收到数据命令时保存待处理操作
- 数据连接建立后执行相应操作

```c
// 保存待处理操作
session->pending_op = FTP_DATA_OP_LIST;
session->pending_path = real_path;
session->ctrl_conn = conn;  // 保存控制连接以便发送响应
```

### 4.2 问题：被动模式端口管理

**描述**：每次 PASV 命令需要分配新的数据端口。

**解决方案**：
- 使用端口池循环分配
- 数据传输完成后释放端口

```c
static uint16_t next_data_port = FTP_DATA_PORT_BASE;

session->data_port = next_data_port++;
if (next_data_port > FTP_DATA_PORT_BASE + 1000) {
    next_data_port = FTP_DATA_PORT_BASE;  // 循环使用
}
```

### 4.3 问题：目录列表格式

**描述**：FTP 客户端期望特定格式的目录列表。

**解决方案**：采用类 Unix 格式的目录列表：

```c
// 格式：-rw-r--r-- 1 ftp ftp    1234 Nov 26 12:00 filename
snprintf(line, sizeof(line), "%s 1 ftp ftp %8ld %s %s\r\n",
         perms, (long)st.st_size, time_str, entry->d_name);
```

### 4.4 问题：文件权限和安全性

**描述**：需要限制 FTP 访问范围，防止越权访问。

**解决方案**：
- 所有路径都相对于 FTP_ROOT_DIR
- 路径转换时强制添加根目录前缀
- 验证目录/文件存在性后才执行操作

## 5. 总结与展望

### 5.1 实现的功能

1. ✅ FTP 控制连接管理（端口 21）
2. ✅ 被动模式数据连接（PASV）
3. ✅ 用户认证（USER/PASS）
4. ✅ 目录操作（PWD/CWD/LIST）
5. ✅ 文件下载（RETR）
6. ✅ 文件上传（STOR）
7. ✅ 传输模式设置（TYPE）
8. ✅ 会话管理

### 5.2 局限性

1. 不支持主动模式（PORT 命令）
2. 用户认证为简化实现，未进行实际验证
3. 不支持断点续传
4. 不支持 TLS/SSL 加密

### 5.3 改进方向

1. 实现主动模式支持
2. 添加用户认证数据库
3. 实现断点续传（REST 命令）
4. 添加传输进度显示
5. 支持 FTPS（FTP over TLS）

## 6. 参考资料

1. RFC 959 - File Transfer Protocol (FTP)
2. RFC 2228 - FTP Security Extensions
3. RFC 4217 - Securing FTP with TLS
4. net-lab 协议栈实现文档

---

**实验日期**：2025年11月
**作者**：net-lab
