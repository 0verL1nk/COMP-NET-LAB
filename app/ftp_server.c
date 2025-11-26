/**
 * @file ftp_server.c
 * @brief 简易 FTP 服务器实现
 *
 * 基于 RFC 959 标准实现的简易 FTP 服务器，支持以下功能：
 * - 控制连接（端口 21）管理
 * - 被动模式（PASV）数据连接
 * - 基本 FTP 命令：USER, PASS, SYST, PWD, CWD, LIST, RETR, STOR, TYPE, PASV, QUIT
 *
 */

#include "driver.h"
#include "net.h"
#include "tcp.h"

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ========================= FTP 配置常量 ========================= */
#define FTP_CTRL_PORT 21           // FTP 控制连接端口
#define FTP_DATA_PORT_BASE 20000   // 被动模式数据端口起始值
#define FTP_MAX_PATH_LENGTH 512    // 最大路径长度
#define FTP_MAX_CMD_LENGTH 256     // 最大命令长度
#define FTP_MAX_RESPONSE_LENGTH 1024  // 最大响应长度
#define FTP_BUFFER_SIZE 4096       // 数据传输缓冲区大小
#define FTP_MAX_SESSIONS 16        // 最大同时会话数

/* ========================= FTP 响应码 ========================= */
#define FTP_RESP_READY           "220"
#define FTP_RESP_GOODBYE         "221"
#define FTP_RESP_TRANSFER_OK     "226"
#define FTP_RESP_PASV_OK         "227"
#define FTP_RESP_LOGIN_OK        "230"
#define FTP_RESP_FILE_ACTION_OK  "250"
#define FTP_RESP_PATH_CREATED    "257"
#define FTP_RESP_NEED_PASSWORD   "331"
#define FTP_RESP_NEED_ACCOUNT    "332"
#define FTP_RESP_FILE_PENDING    "350"
#define FTP_RESP_SERVICE_NA      "421"
#define FTP_RESP_CANT_OPEN_DATA  "425"
#define FTP_RESP_CONN_CLOSED     "426"
#define FTP_RESP_FILE_UNAVAIL    "450"
#define FTP_RESP_LOCAL_ERROR     "451"
#define FTP_RESP_INSUFFICIENT    "452"
#define FTP_RESP_SYNTAX_ERROR    "500"
#define FTP_RESP_PARAM_ERROR     "501"
#define FTP_RESP_CMD_NOT_IMPL    "502"
#define FTP_RESP_BAD_SEQUENCE    "503"
#define FTP_RESP_NOT_LOGGED_IN   "530"
#define FTP_RESP_FILE_NOT_FOUND  "550"
#define FTP_RESP_TYPE_OK         "200"
#define FTP_RESP_SYST_OK         "215"

/* ========================= FTP 会话状态 ========================= */
typedef enum {
    FTP_STATE_CONNECTED,     // 已连接，等待用户名
    FTP_STATE_USER_OK,       // 用户名已接收，等待密码
    FTP_STATE_LOGGED_IN,     // 已登录
    FTP_STATE_PASV_WAIT,     // 等待被动模式数据连接
    FTP_STATE_DATA_TRANSFER  // 数据传输中
} ftp_state_t;

/* ========================= FTP 传输类型 ========================= */
typedef enum {
    FTP_TYPE_ASCII,          // ASCII 模式
    FTP_TYPE_BINARY          // 二进制模式
} ftp_transfer_type_t;

/* ========================= FTP 数据传输操作类型 ========================= */
typedef enum {
    FTP_DATA_OP_NONE,        // 无操作
    FTP_DATA_OP_LIST,        // 目录列表
    FTP_DATA_OP_RETR,        // 下载文件
    FTP_DATA_OP_STOR         // 上传文件
} ftp_data_op_t;

/* ========================= FTP 会话结构 ========================= */
typedef struct {
    uint8_t active;                          // 会话是否活跃
    uint8_t client_ip[NET_IP_LEN];          // 客户端 IP
    uint16_t client_port;                    // 客户端端口
    ftp_state_t state;                       // 会话状态
    ftp_transfer_type_t transfer_type;       // 传输类型
    char current_dir[FTP_MAX_PATH_LENGTH];   // 当前目录（相对于 FTP 根目录）
    char username[64];                       // 用户名
    uint16_t data_port;                      // 被动模式数据端口
    ftp_data_op_t pending_op;                // 待处理的数据操作
    char pending_path[FTP_MAX_PATH_LENGTH];  // 待处理的文件路径
    tcp_conn_t *ctrl_conn;                   // 控制连接
} ftp_session_t;

/* ========================= 全局变量 ========================= */
static ftp_session_t ftp_sessions[FTP_MAX_SESSIONS];
static uint16_t next_data_port = FTP_DATA_PORT_BASE;

/* ========================= 工具函数 ========================= */

/**
 * @brief 获取完整的文件系统路径
 *
 * @param session FTP 会话
 * @param path    FTP 路径（可以是绝对路径或相对路径）
 * @param out     输出缓冲区
 * @param out_len 输出缓冲区大小
 */
static void ftp_get_real_path(ftp_session_t *session, const char *path, char *out, size_t out_len) {
    if (path[0] == '/') {
        // 绝对路径
        snprintf(out, out_len, "%s%s", FTP_ROOT_DIR, path);
    } else {
        // 相对路径
        if (strcmp(session->current_dir, "/") == 0) {
            snprintf(out, out_len, "%s/%s", FTP_ROOT_DIR, path);
        } else {
            snprintf(out, out_len, "%s%s/%s", FTP_ROOT_DIR, session->current_dir, path);
        }
    }
}

/**
 * @brief 查找或创建 FTP 会话
 */
static ftp_session_t *ftp_get_session(uint8_t *client_ip, uint16_t client_port, int create) {
    ftp_session_t *free_session = NULL;

    for (int i = 0; i < FTP_MAX_SESSIONS; i++) {
        if (ftp_sessions[i].active &&
            memcmp(ftp_sessions[i].client_ip, client_ip, NET_IP_LEN) == 0 &&
            ftp_sessions[i].client_port == client_port) {
            return &ftp_sessions[i];
        }
        if (!ftp_sessions[i].active && !free_session) {
            free_session = &ftp_sessions[i];
        }
    }

    if (create && free_session) {
        memset(free_session, 0, sizeof(ftp_session_t));
        free_session->active = 1;
        memcpy(free_session->client_ip, client_ip, NET_IP_LEN);
        free_session->client_port = client_port;
        free_session->state = FTP_STATE_CONNECTED;
        free_session->transfer_type = FTP_TYPE_ASCII;
        strcpy(free_session->current_dir, "/");
        return free_session;
    }

    return NULL;
}

/**
 * @brief 通过数据端口查找 FTP 会话
 */
static ftp_session_t *ftp_get_session_by_data_port(uint16_t data_port) {
    for (int i = 0; i < FTP_MAX_SESSIONS; i++) {
        if (ftp_sessions[i].active && ftp_sessions[i].data_port == data_port) {
            return &ftp_sessions[i];
        }
    }
    return NULL;
}

/**
 * @brief 关闭 FTP 会话
 */
static void ftp_close_session(ftp_session_t *session) {
    if (session->data_port > 0) {
        tcp_close(session->data_port);
    }
    session->active = 0;
}

/**
 * @brief 发送 FTP 响应
 */
static void ftp_send_response(tcp_conn_t *conn, uint16_t port, uint8_t *dst_ip, uint16_t dst_port,
                               const char *code, const char *message) {
    char response[FTP_MAX_RESPONSE_LENGTH];
    int len = snprintf(response, sizeof(response), "%s %s\r\n", code, message);
    tcp_send(conn, (uint8_t *)response, len, port, dst_ip, dst_port);
    printf("[FTP] -> %s %s\n", code, message);
}

/**
 * @brief 检查文件是否存在且可读
 */
static int ftp_check_file_readable(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

/**
 * @brief 检查目录是否存在
 */
static int ftp_check_dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

/**
 * @brief 检查是否有足够空间写入文件
 */
static int ftp_check_space_available(const char *path, size_t size) {
    // 简化实现：假设总是有足够空间
    (void)path;
    (void)size;
    return 1;
}

/**
 * @brief 检查写入权限
 */
static int ftp_check_write_permission(const char *path) {
    // 尝试以追加模式打开文件来检查权限
    FILE *f = fopen(path, "ab");
    if (f) {
        fclose(f);
        return 1;
    }
    // 如果文件不存在，检查父目录权限
    char parent[FTP_MAX_PATH_LENGTH];
    strncpy(parent, path, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char *last_slash = strrchr(parent, '/');
    if (last_slash) {
        *last_slash = '\0';
        return access(parent, W_OK) == 0;
    }
    return 0;
}

/* ========================= FTP 命令处理函数 ========================= */

/**
 * @brief 处理 USER 命令
 */
static void ftp_cmd_user(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    strncpy(session->username, arg, sizeof(session->username) - 1);
    session->state = FTP_STATE_USER_OK;
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_NEED_PASSWORD,
                      "User name okay, need password.");
}

/**
 * @brief 处理 PASS 命令
 */
static void ftp_cmd_pass(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    (void)arg;  // 简化实现：不验证密码
    if (session->state != FTP_STATE_USER_OK) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_BAD_SEQUENCE,
                          "Login with USER first.");
        return;
    }
    session->state = FTP_STATE_LOGGED_IN;
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_LOGIN_OK,
                      "User logged in, proceed.");
}

/**
 * @brief 处理 SYST 命令
 */
static void ftp_cmd_syst(ftp_session_t *session, tcp_conn_t *conn,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    (void)session;
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_SYST_OK, "UNIX Type: L8");
}

/**
 * @brief 处理 PWD 命令
 */
static void ftp_cmd_pwd(ftp_session_t *session, tcp_conn_t *conn,
                         uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    char response[FTP_MAX_RESPONSE_LENGTH];
    snprintf(response, sizeof(response), "\"%s\" is current directory.", session->current_dir);
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_PATH_CREATED, response);
}

/**
 * @brief 处理 CWD 命令
 */
static void ftp_cmd_cwd(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                         uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    char real_path[FTP_MAX_PATH_LENGTH];
    char new_dir[FTP_MAX_PATH_LENGTH];

    if (arg[0] == '/') {
        // 绝对路径
        strncpy(new_dir, arg, sizeof(new_dir) - 1);
        new_dir[sizeof(new_dir) - 1] = '\0';
    } else if (strcmp(arg, "..") == 0) {
        // 返回上一级目录
        strncpy(new_dir, session->current_dir, sizeof(new_dir) - 1);
        new_dir[sizeof(new_dir) - 1] = '\0';
        char *last_slash = strrchr(new_dir, '/');
        if (last_slash && last_slash != new_dir) {
            *last_slash = '\0';
        } else {
            strcpy(new_dir, "/");
        }
    } else {
        // 相对路径
        if (strcmp(session->current_dir, "/") == 0) {
            snprintf(new_dir, sizeof(new_dir), "/%s", arg);
        } else {
            snprintf(new_dir, sizeof(new_dir), "%s/%s", session->current_dir, arg);
        }
    }

    snprintf(real_path, sizeof(real_path), "%s%s", FTP_ROOT_DIR, new_dir);

    if (ftp_check_dir_exists(real_path)) {
        strncpy(session->current_dir, new_dir, sizeof(session->current_dir) - 1);
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_FILE_ACTION_OK,
                          "Directory successfully changed.");
    } else {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_FILE_NOT_FOUND,
                          "Failed to change directory.");
    }
}

/**
 * @brief 处理 TYPE 命令
 */
static void ftp_cmd_type(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    if (arg[0] == 'A' || arg[0] == 'a') {
        session->transfer_type = FTP_TYPE_ASCII;
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_TYPE_OK, "Switching to ASCII mode.");
    } else if (arg[0] == 'I' || arg[0] == 'i') {
        session->transfer_type = FTP_TYPE_BINARY;
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_TYPE_OK, "Switching to Binary mode.");
    } else {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_PARAM_ERROR,
                          "Unrecognized TYPE command.");
    }
}

/* ========================= 数据连接处理 ========================= */

/**
 * @brief 数据连接处理函数
 */
static void ftp_data_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len,
                              uint8_t *src_ip, uint16_t src_port);

/**
 * @brief 处理 PASV 命令
 */
static void ftp_cmd_pasv(ftp_session_t *session, tcp_conn_t *conn,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    // 分配数据端口
    session->data_port = next_data_port++;
    if (next_data_port > FTP_DATA_PORT_BASE + 1000) {
        next_data_port = FTP_DATA_PORT_BASE;
    }

    // 打开数据端口监听
    tcp_open(session->data_port, ftp_data_handler);
    session->state = FTP_STATE_PASV_WAIT;

    // 格式化 PASV 响应
    // 格式: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    char response[FTP_MAX_RESPONSE_LENGTH];
    uint8_t p1 = (session->data_port >> 8) & 0xFF;
    uint8_t p2 = session->data_port & 0xFF;
    snprintf(response, sizeof(response),
             "Entering Passive Mode (%d,%d,%d,%d,%d,%d).",
             net_if_ip[0], net_if_ip[1], net_if_ip[2], net_if_ip[3], p1, p2);
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_PASV_OK, response);

    printf("[FTP] Passive mode, data port: %d\n", session->data_port);
}

/**
 * @brief 处理 LIST 命令
 */
static void ftp_cmd_list(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    if (session->state != FTP_STATE_PASV_WAIT && session->state != FTP_STATE_LOGGED_IN) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_CANT_OPEN_DATA,
                          "Use PASV first.");
        return;
    }

    char real_path[FTP_MAX_PATH_LENGTH];
    if (arg && strlen(arg) > 0) {
        ftp_get_real_path(session, arg, real_path, sizeof(real_path));
    } else {
        snprintf(real_path, sizeof(real_path), "%s%s", FTP_ROOT_DIR, session->current_dir);
    }

    session->pending_op = FTP_DATA_OP_LIST;
    strncpy(session->pending_path, real_path, sizeof(session->pending_path) - 1);
    session->ctrl_conn = conn;

    ftp_send_response(conn, port, dst_ip, dst_port, "150",
                      "Here comes the directory listing.");
}

/**
 * @brief 处理 RETR 命令（下载文件）
 */
static void ftp_cmd_retr(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    if (session->state != FTP_STATE_PASV_WAIT && session->state != FTP_STATE_LOGGED_IN) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_CANT_OPEN_DATA,
                          "Use PASV first.");
        return;
    }

    if (!arg || strlen(arg) == 0) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_PARAM_ERROR,
                          "RETR requires filename.");
        return;
    }

    char real_path[FTP_MAX_PATH_LENGTH];
    ftp_get_real_path(session, arg, real_path, sizeof(real_path));

    // 检查文件是否存在且可读
    if (!ftp_check_file_readable(real_path)) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_FILE_NOT_FOUND,
                          "File not found or not readable.");
        return;
    }

    session->pending_op = FTP_DATA_OP_RETR;
    strncpy(session->pending_path, real_path, sizeof(session->pending_path) - 1);
    session->ctrl_conn = conn;

    ftp_send_response(conn, port, dst_ip, dst_port, "150",
                      "Opening data connection for file transfer.");
}

/**
 * @brief 处理 STOR 命令（上传文件）
 */
static void ftp_cmd_stor(ftp_session_t *session, tcp_conn_t *conn, const char *arg,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    if (session->state != FTP_STATE_PASV_WAIT && session->state != FTP_STATE_LOGGED_IN) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_CANT_OPEN_DATA,
                          "Use PASV first.");
        return;
    }

    if (!arg || strlen(arg) == 0) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_PARAM_ERROR,
                          "STOR requires filename.");
        return;
    }

    char real_path[FTP_MAX_PATH_LENGTH];
    ftp_get_real_path(session, arg, real_path, sizeof(real_path));

    // 检查写入权限
    if (!ftp_check_write_permission(real_path)) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_FILE_NOT_FOUND,
                          "Permission denied.");
        return;
    }

    // 检查空间是否足够（简化实现）
    if (!ftp_check_space_available(real_path, 0)) {
        ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_INSUFFICIENT,
                          "Insufficient storage space.");
        return;
    }

    session->pending_op = FTP_DATA_OP_STOR;
    strncpy(session->pending_path, real_path, sizeof(session->pending_path) - 1);
    session->ctrl_conn = conn;

    ftp_send_response(conn, port, dst_ip, dst_port, "150",
                      "OK to send data.");
}

/**
 * @brief 处理 QUIT 命令
 */
static void ftp_cmd_quit(ftp_session_t *session, tcp_conn_t *conn,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_GOODBYE, "Goodbye.");
    ftp_close_session(session);
}

/**
 * @brief 处理 NOOP 命令
 */
static void ftp_cmd_noop(ftp_session_t *session, tcp_conn_t *conn,
                          uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    (void)session;
    ftp_send_response(conn, port, dst_ip, dst_port, FTP_RESP_TYPE_OK, "NOOP ok.");
}

/* ========================= 数据传输实现 ========================= */

/**
 * @brief 执行目录列表
 */
static void ftp_do_list(ftp_session_t *session, tcp_conn_t *data_conn,
                         uint16_t data_port, uint8_t *dst_ip, uint16_t dst_port) {
    DIR *dir = opendir(session->pending_path);
    if (!dir) {
        printf("[FTP] Cannot open directory: %s\n", session->pending_path);
        return;
    }

    struct dirent *entry;
    char line[512];
    struct stat st;
    char full_path[FTP_MAX_PATH_LENGTH];

    while ((entry = readdir(dir)) != NULL) {
        // 跳过 . 和 ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", session->pending_path, entry->d_name);

        if (stat(full_path, &st) == 0) {
            char perms[11] = "----------";
            perms[0] = S_ISDIR(st.st_mode) ? 'd' : '-';
            perms[1] = (st.st_mode & S_IRUSR) ? 'r' : '-';
            perms[2] = (st.st_mode & S_IWUSR) ? 'w' : '-';
            perms[3] = (st.st_mode & S_IXUSR) ? 'x' : '-';
            perms[4] = (st.st_mode & S_IRGRP) ? 'r' : '-';
            perms[5] = (st.st_mode & S_IWGRP) ? 'w' : '-';
            perms[6] = (st.st_mode & S_IXGRP) ? 'x' : '-';
            perms[7] = (st.st_mode & S_IROTH) ? 'r' : '-';
            perms[8] = (st.st_mode & S_IWOTH) ? 'w' : '-';
            perms[9] = (st.st_mode & S_IXOTH) ? 'x' : '-';

            struct tm *tm = localtime(&st.st_mtime);
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%b %d %H:%M", tm);

            int len = snprintf(line, sizeof(line), "%s 1 ftp ftp %8ld %s %s\r\n",
                               perms, (long)st.st_size, time_str, entry->d_name);
            tcp_send(data_conn, (uint8_t *)line, len, data_port, dst_ip, dst_port);
        }
    }

    closedir(dir);
}

/**
 * @brief 执行文件下载
 */
static void ftp_do_retr(ftp_session_t *session, tcp_conn_t *data_conn,
                         uint16_t data_port, uint8_t *dst_ip, uint16_t dst_port) {
    FILE *file = fopen(session->pending_path, "rb");
    if (!file) {
        printf("[FTP] Cannot open file: %s\n", session->pending_path);
        return;
    }

    char buffer[FTP_BUFFER_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        tcp_send(data_conn, (uint8_t *)buffer, bytes_read, data_port, dst_ip, dst_port);
    }

    fclose(file);
    printf("[FTP] File sent: %s\n", session->pending_path);
}

/**
 * @brief 执行文件上传（接收数据）
 */
static void ftp_do_stor_receive(ftp_session_t *session, uint8_t *data, size_t len) {
    FILE *file = fopen(session->pending_path, "ab");
    if (!file) {
        printf("[FTP] Cannot open file for writing: %s\n", session->pending_path);
        return;
    }

    fwrite(data, 1, len, file);
    fclose(file);
    printf("[FTP] Received %zu bytes for: %s\n", len, session->pending_path);
}

/**
 * @brief 数据连接处理函数
 */
static void ftp_data_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len,
                              uint8_t *src_ip, uint16_t src_port) {
    // 找到对应的会话
    // 注意：需要根据数据端口查找会话
    ftp_session_t *session = NULL;
    for (int i = 0; i < FTP_MAX_SESSIONS; i++) {
        if (ftp_sessions[i].active && ftp_sessions[i].data_port > 0) {
            session = &ftp_sessions[i];
            break;
        }
    }

    if (!session) {
        printf("[FTP] No session found for data connection\n");
        return;
    }

    switch (session->pending_op) {
        case FTP_DATA_OP_LIST:
            ftp_do_list(session, tcp_conn, session->data_port, src_ip, src_port);
            // 发送完成响应到控制连接
            if (session->ctrl_conn) {
                ftp_send_response(session->ctrl_conn, FTP_CTRL_PORT,
                                  session->client_ip, session->client_port,
                                  FTP_RESP_TRANSFER_OK, "Directory send OK.");
            }
            break;

        case FTP_DATA_OP_RETR:
            ftp_do_retr(session, tcp_conn, session->data_port, src_ip, src_port);
            if (session->ctrl_conn) {
                ftp_send_response(session->ctrl_conn, FTP_CTRL_PORT,
                                  session->client_ip, session->client_port,
                                  FTP_RESP_TRANSFER_OK, "Transfer complete.");
            }
            break;

        case FTP_DATA_OP_STOR:
            if (len > 0) {
                ftp_do_stor_receive(session, data, len);
            }
            // 注意：实际上 STOR 完成判断需要更复杂的逻辑
            break;

        default:
            break;
    }

    // 关闭数据端口
    tcp_close(session->data_port);
    session->data_port = 0;
    session->pending_op = FTP_DATA_OP_NONE;
    session->state = FTP_STATE_LOGGED_IN;
}

/* ========================= 控制连接处理 ========================= */

/**
 * @brief FTP 控制连接处理函数
 */
void ftp_ctrl_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port) {
    // 确保数据以 null 结尾
    char cmd_buf[FTP_MAX_CMD_LENGTH];
    size_t copy_len = (len < sizeof(cmd_buf) - 1) ? len : sizeof(cmd_buf) - 1;
    memcpy(cmd_buf, data, copy_len);
    cmd_buf[copy_len] = '\0';

    // 移除末尾的 \r\n
    char *crlf = strstr(cmd_buf, "\r\n");
    if (crlf) *crlf = '\0';
    char *lf = strchr(cmd_buf, '\n');
    if (lf) *lf = '\0';
    char *cr = strchr(cmd_buf, '\r');
    if (cr) *cr = '\0';

    printf("[FTP] <- %s\n", cmd_buf);

    // 解析命令和参数
    char cmd[16] = {0};
    char arg[FTP_MAX_CMD_LENGTH] = {0};
    sscanf(cmd_buf, "%15s %[^\n]", cmd, arg);

    // 转换命令为大写
    for (int i = 0; cmd[i]; i++) {
        if (cmd[i] >= 'a' && cmd[i] <= 'z') {
            cmd[i] -= 32;
        }
    }

    // 获取或创建会话
    ftp_session_t *session = ftp_get_session(src_ip, src_port, 1);
    if (!session) {
        ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                          FTP_RESP_SERVICE_NA, "Too many connections.");
        return;
    }

    session->ctrl_conn = tcp_conn;

    // 处理命令
    if (strcmp(cmd, "USER") == 0) {
        ftp_cmd_user(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
    } else if (strcmp(cmd, "PASS") == 0) {
        ftp_cmd_pass(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
    } else if (strcmp(cmd, "SYST") == 0) {
        ftp_cmd_syst(session, tcp_conn, FTP_CTRL_PORT, src_ip, src_port);
    } else if (strcmp(cmd, "PWD") == 0 || strcmp(cmd, "XPWD") == 0) {
        if (session->state != FTP_STATE_LOGGED_IN && session->state != FTP_STATE_PASV_WAIT) {
            ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                              FTP_RESP_NOT_LOGGED_IN, "Please login first.");
        } else {
            ftp_cmd_pwd(session, tcp_conn, FTP_CTRL_PORT, src_ip, src_port);
        }
    } else if (strcmp(cmd, "CWD") == 0) {
        if (session->state != FTP_STATE_LOGGED_IN && session->state != FTP_STATE_PASV_WAIT) {
            ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                              FTP_RESP_NOT_LOGGED_IN, "Please login first.");
        } else {
            ftp_cmd_cwd(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
        }
    } else if (strcmp(cmd, "TYPE") == 0) {
        ftp_cmd_type(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
    } else if (strcmp(cmd, "PASV") == 0) {
        if (session->state != FTP_STATE_LOGGED_IN && session->state != FTP_STATE_PASV_WAIT) {
            ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                              FTP_RESP_NOT_LOGGED_IN, "Please login first.");
        } else {
            ftp_cmd_pasv(session, tcp_conn, FTP_CTRL_PORT, src_ip, src_port);
        }
    } else if (strcmp(cmd, "LIST") == 0) {
        if (session->state != FTP_STATE_LOGGED_IN && session->state != FTP_STATE_PASV_WAIT) {
            ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                              FTP_RESP_NOT_LOGGED_IN, "Please login first.");
        } else {
            ftp_cmd_list(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
        }
    } else if (strcmp(cmd, "RETR") == 0) {
        if (session->state != FTP_STATE_LOGGED_IN && session->state != FTP_STATE_PASV_WAIT) {
            ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                              FTP_RESP_NOT_LOGGED_IN, "Please login first.");
        } else {
            ftp_cmd_retr(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
        }
    } else if (strcmp(cmd, "STOR") == 0) {
        if (session->state != FTP_STATE_LOGGED_IN && session->state != FTP_STATE_PASV_WAIT) {
            ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                              FTP_RESP_NOT_LOGGED_IN, "Please login first.");
        } else {
            ftp_cmd_stor(session, tcp_conn, arg, FTP_CTRL_PORT, src_ip, src_port);
        }
    } else if (strcmp(cmd, "QUIT") == 0) {
        ftp_cmd_quit(session, tcp_conn, FTP_CTRL_PORT, src_ip, src_port);
    } else if (strcmp(cmd, "NOOP") == 0) {
        ftp_cmd_noop(session, tcp_conn, FTP_CTRL_PORT, src_ip, src_port);
    } else if (strcmp(cmd, "FEAT") == 0) {
        // 特性列表
        ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                          "211", "Features:\r\n PASV\r\n UTF8\r\n211 End");
    } else if (strcmp(cmd, "OPTS") == 0) {
        // 选项命令
        ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                          FTP_RESP_TYPE_OK, "Option set.");
    } else {
        ftp_send_response(tcp_conn, FTP_CTRL_PORT, src_ip, src_port,
                          FTP_RESP_CMD_NOT_IMPL, "Command not implemented.");
    }
}

/**
 * @brief 发送欢迎消息（当有新连接时）
 */
void ftp_send_welcome(tcp_conn_t *tcp_conn, uint8_t *dst_ip, uint16_t dst_port) {
    ftp_send_response(tcp_conn, FTP_CTRL_PORT, dst_ip, dst_port,
                      FTP_RESP_READY, "Welcome to Simple FTP Server.");
}

/* ========================= 主函数 ========================= */

int main(int argc, char const *argv[]) {
    printf("==============================================\n");
    printf("    Simple FTP Server based on net-lab\n");
    printf("==============================================\n");
    printf("FTP Root Directory: %s\n", FTP_ROOT_DIR);
    printf("Control Port: %d\n", FTP_CTRL_PORT);
    printf("==============================================\n");

    // 初始化协议栈
    if (net_init() == -1) {
        printf("[FTP] Network initialization failed.\n");
        return -1;
    }

    // 初始化会话表
    memset(ftp_sessions, 0, sizeof(ftp_sessions));

    // 注册 FTP 控制端口监听
    tcp_open(FTP_CTRL_PORT, ftp_ctrl_handler);

    printf("[FTP] Server started, listening on port %d...\n", FTP_CTRL_PORT);

    // 主循环
    while (1) {
        net_poll();
    }

    return 0;
}
