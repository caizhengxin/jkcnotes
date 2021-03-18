/*
 * @Author: JanKinCai
 * @Date:   2020-11-23 10:24:55
 * @Last Modified by:   jankincai
 * @Last Modified time: 2021-03-18 10:09:33
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netlink.h>
#include <net/icmp.h>
#include <net/sock.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include "ipt_TEST.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("JanKin Cai <caizhengxin@bolean.com.cn>");
MODULE_DESCRIPTION("Xtables: packet test target for IPv4");


struct sock *nlsk = NULL;
extern struct net init_net;


__u8 portlist[65535] = {0};


static int send_usrmsg(char *pbuf, uint16_t len) {
  struct sk_buff *nl_skb;
  struct nlmsghdr *nlh;

  int ret;

  /* 创建sk_buff 空间 */
  nl_skb = nlmsg_new(len, GFP_ATOMIC);
  if (!nl_skb)
  {
    printk("netlink alloc failure\n");
    return -1;
  }

  /* 设置netlink消息头部 */
  nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, len, 0);
  if (nlh == NULL)
  {
    printk("nlmsg_put failaure \n");
    nlmsg_free(nl_skb);
    return -1;
  }

  /* 拷贝数据发送 */
  memcpy(nlmsg_data(nlh), pbuf, len);
  ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);

  return ret;
}


static unsigned int test_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    const struct ipt_test_info *test = par->targinfo;
    int hook = xt_hooknum(par);
    // struct net *net = xt_net(par);

    struct pktinfo pktinfo_v;

    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct ethhdr *ethh = eth_hdr(skb);
    char buf[400] = {0};

    pktinfo_v.mark = skb->mark;
    pktinfo_v.dire = DIRECTION_UNKNOWN;

    memcpy(pktinfo_v.h_dest, ethh->h_dest, sizeof(ethh->h_dest));
    memcpy(pktinfo_v.h_source, ethh->h_source, sizeof(ethh->h_source));

    /* IPv4 */
    iph = ip_hdr(skb);

    pktinfo_v.protocol = iph->protocol;
    pktinfo_v.saddr = iph->saddr;
    pktinfo_v.daddr = iph->daddr;
    pktinfo_v.tot_len = ntohs(iph->tot_len);

    if (iph->protocol == 6)
    {
        /* TCP */
        tcph = tcp_hdr(skb);

        pktinfo_v.sport = ntohs(tcph->source);
        pktinfo_v.dport = ntohs(tcph->dest);

        if (tcph->syn)
        {
            portlist[pktinfo_v.dport] = 1;
        }
        else if (tcph->syn && tcph->ack)
        {
            /* 第二次握手，缓存dport */
            portlist[pktinfo_v.sport] = 1;
        }
    }
    else if (iph->protocol == 17)
    {
        /* UDP */
        udph = udp_hdr(skb);

        pktinfo_v.sport = ntohs(udph->source);
        pktinfo_v.dport = ntohs(udph->dest);

        /* 第一个UDP包，缓存dport */
        if (portlist[pktinfo_v.sport] == 0 && portlist[pktinfo_v.dport] == 0)
        {
            portlist[pktinfo_v.dport] = 1;
        }
    }
    else if (iph->protocol == 1)
    {
        icmph = icmp_hdr(skb);

        if (icmph->type == 8)
        {
            pktinfo_v.dire = DIRECTION_REQ;
        }
        else
        {
            pktinfo_v.dire = DIRECTION_RESP;
        }
    }

    /* 方向 */
    if (iph->protocol == 6 || iph->protocol == 17)
    {
        if (portlist[pktinfo_v.sport])
        {
            pktinfo_v.dire = DIRECTION_RESP;
        }
        else if (portlist[pktinfo_v.dport])
        {
            pktinfo_v.dire = DIRECTION_REQ;
        }
        else
        {
            if (pktinfo_v.sport < pktinfo_v.dport)
            {
                pktinfo_v.dire = DIRECTION_RESP;
            }
            else
            {
                pktinfo_v.dire = DIRECTION_REQ;
            }
        }
    }

    pktinfo_v.target = test->target;
    pktinfo_v.id = test->id;

    memcpy(buf, &pktinfo_v, sizeof(pktinfo_v));
    send_usrmsg(buf, sizeof(pktinfo_v));

    // 无法实现RETURN，https://github.com/torvalds/linux/blob/master/net/ipv4/netfilter/ip_tables.c

    switch (test->target)
    {
        case TARGET_ACCEPT:
            return NF_ACCEPT;
        case TARGET_DROP:
            return NF_DROP;
        case TARGET_REJECT:
            // https://github.com/torvalds/linux/blob/master/net/ipv4/netfilter/ipt_REJECT.c
            switch (iph->protocol)
            {
                case 6:                 /* TCP */
                    nf_send_reset(xt_net(par), skb, hook);
                    break;
                case 17:                 /* UDP */
                    // nf_send_unreach(skb, ICMP_NET_UNREACH, hook);   /* 网络不可达 */
                    // nf_send_unreach(skb, ICMP_HOST_UNREACH, hook);  /* 主机不可达 */
                    // nf_send_unreach(skb, ICMP_PROT_UNREACH, hook);  /* 协议不可用 */
                    nf_send_unreach(skb, ICMP_PORT_UNREACH, hook);  /* 端口不可达 */
                    // nf_send_unreach(skb, ICMP_NET_ANO, hook);
                    // nf_send_unreach(skb, ICMP_HOST_ANO, hook);
                    // nf_send_unreach(skb, ICMP_PKT_FILTERED, hook);
                    // nf_send_reset(xt_net(par), skb, hook);
                    break;
            }

            return NF_DROP;
        case TARGET_ALERT:
            /* 告警完成，直接放行 */
            return NF_ACCEPT;
        case TARGET_LOG:
            return XT_CONTINUE;
    }

    return NF_ACCEPT;
}


static struct xt_target test_tg_reg __read_mostly = {
    .name       = "TEST",
    .family     = NFPROTO_IPV4,
    .target     = test_tg,
    .targetsize = sizeof(struct ipt_test_info),
    // .table      = "filter",
    .hooks      =   (1 << NF_INET_PRE_ROUTING) |
                    (1 << NF_INET_LOCAL_IN) |
                    (1 << NF_INET_FORWARD) |
                    (1 << NF_INET_LOCAL_OUT) |
                    (1 << NF_INET_POST_ROUTING),
    .me         = THIS_MODULE,
};

static int __init test_tg_init(void)
{
    nlsk = (struct sock*)netlink_kernel_create(&init_net, NETLINK_TEST, NULL);

    if (nlsk == NULL)
    {
        printk("netlink_kernel_create error\n");
    }

    return xt_register_target(&test_tg_reg);
}

static void __exit test_tg_exit(void)
{
    if (nlsk)
    {
        netlink_kernel_release(nlsk);
        nlsk = NULL;
    }

    xt_unregister_target(&test_tg_reg);
}

module_init(test_tg_init);
module_exit(test_tg_exit);
