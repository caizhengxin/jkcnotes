/*
 * @Author: JanKinCai
 * @Date:   2020-11-23 11:06:06
 * @Last Modified by:   jankincai
 * @Last Modified time: 2021-03-18 10:13:49
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include "ipt_TEST.h"

#define MAX_PAYLOAD   1024

struct value_string
{
    const char          *ptr;
};


static const struct value_string target_map[] = {
    { NULL },
    { "ALERT" },
    { "DROP" },
    { "REJECT" },
    { "ACCEPT" },
    { "LOG" },
};


struct sockaddr_nl src_addr, dest_addr;
struct msghdr msg;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd = -1;


void print_mac(uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X ", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


void print_addr(uint32_t addr)
{
    printf("%d.%d.%d.%d ", addr & 0x000000ff, (addr >> 8) & 0x000000ff, (addr >> 16) & 0x000000ff, addr >> 24);
}


int main(int argc, char const *argv[])
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);

    if (sock_fd == -1)
    {
        perror("can't create netlink socket!");
        exit(1);
    }

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&msg, 0, sizeof(msg));

    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = USER_PORT; //对应内核发送的pid
    src_addr.nl_groups = 0;
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Waiting for message from kernel\n");

    while (1)
    {
        if (recvmsg(sock_fd, &msg, 0) != 1)
        {
            struct pktinfo *pktinfo_v = (struct pktinfo*)NLMSG_DATA(nlh);

            printf(">>> target=%s (%d), id=%d\n", target_map[pktinfo_v->target].ptr, pktinfo_v->target, pktinfo_v->id);
            print_mac(pktinfo_v->h_source);
            print_addr(pktinfo_v->saddr);

            if ((pktinfo_v->protocol == 6) || (pktinfo_v->protocol == 7))
            {
                printf("%d ", pktinfo_v->sport);
            }

            printf("--> ");

            print_mac(pktinfo_v->h_dest);
            print_addr(pktinfo_v->daddr);

            if ((pktinfo_v->protocol == 6) || (pktinfo_v->protocol == 7))
            {
                printf("%d ", pktinfo_v->dport);
            }

            printf("protocol=%d len=%u mark=%u dire=%d\n", pktinfo_v->protocol, pktinfo_v->tot_len, pktinfo_v->mark, pktinfo_v->dire);
        }
    }

    close(sock_fd);
    free(nlh);

    return 0;
}
