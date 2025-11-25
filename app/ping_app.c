#include "driver.h"
#include "net.h"
#include "icmp.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PING_COUNT 4
#define PING_INTERVAL 1  // 1 second

static uint8_t target_ip[NET_IP_LEN];
static int ping_sent_count = 0;
static time_t last_ping_time = 0;

int parse_ip_address(const char *ip_str, uint8_t *ip) {
    int a, b, c, d;
    if (sscanf(ip_str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return -1;
    }

    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) {
        return -1;
    }

    ip[0] = (uint8_t)a;
    ip[1] = (uint8_t)b;
    ip[2] = (uint8_t)c;
    ip[3] = (uint8_t)d;

    return 0;
}

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_ip>\n", argv[0]);
        printf("Example: %s 192.168.1.1\n", argv[0]);
        return -1;
    }

    // Parse target IP address
    if (parse_ip_address(argv[1], target_ip) != 0) {
        printf("Invalid IP address format: %s\n", argv[1]);
        return -1;
    }

    printf("PING %s (%s): 56 data bytes\n", argv[1], iptos(target_ip));

    if (net_init() == -1) {  // 初始化协议栈
        printf("net init failed.\n");
        return -1;
    }

    last_ping_time = time(NULL);

    while (1) {
        // Check if it's time to send another ping
        time_t current_time = time(NULL);
        if (ping_sent_count < PING_COUNT &&
            current_time - last_ping_time >= PING_INTERVAL) {

            // Send ping request
            icmp_ping_request(target_ip);
            ping_sent_count++;
            last_ping_time = current_time;
        }

        // Poll network
        net_poll();

        // Check if we're done
        if (ping_sent_count >= PING_COUNT && icmp_get_pending_requests_count() == 0) {
            // All pings sent and all replies received (or timed out)
            break;
        }

    }

    // Report statistics
    icmp_ping_report_stats();

    return 0;
}