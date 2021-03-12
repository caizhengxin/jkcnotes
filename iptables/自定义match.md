# 自定义match

## 介绍

- 更新中

## 例子

> 内核态头文件

```c++
// ipt_protection.h
#ifndef __IPT_PROTECTION_H__
#define __IPT_PROTECTION_H__

#define PROTECTION_VERSION       "0.1.0"
#define arraysize(x) (sizeof(x) / sizeof((x)[0]))


#define PROTECTION_FLAGS_TYPE         0x01
#define PROTECTION_FLAGS_LENGTH       0x02


enum protection_type
{
    PROTECTION_TYPE_LAND = 1,
    PROTECTION_TYPE_TCP_SCAN,
    PROTECTION_TYPE_ICMP_BIG,
};


struct xt_protection_info {
    bool               invert;

    unsigned char     flags;
    unsigned short     type;

    unsigned short     min_pktsize;
    unsigned short     max_pktsize;
};

#endif /* __IPT_PROTECTION_H__ */
```

> 内核态程序

```c++
/*
 * @Author: jankincai
 * @Date:   2021-03-09 17:31:31
 * @Last Modified by:   jankincai
 * @Last Modified time: 2021-03-12 10:15:45
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_decnet.h>
#include "ipt_protection.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("JanKin Cai <caizhengxin@bolean.com.cn>");
MODULE_DESCRIPTION("Xtables: packet protection match");


#define TCP_FLAGS_NONE    0x0100
#define TCP_FLAGS_URG     0x0020
#define TCP_FLAGS_ACK     0x0010
#define TCP_FLAGS_PSH     0x0008
#define TCP_FLAGS_RST     0x0004
#define TCP_FLAGS_SYN     0x0002
#define TCP_FLAGS_FIN     0x0001

#define TCP_FLAGS_ALL     TCP_FLAGS_NONE | TCP_FLAGS_URG | TCP_FLAGS_ACK | TCP_FLAGS_PSH | TCP_FLAGS_RST | TCP_FLAGS_SYN | TCP_FLAGS_FIN


typedef struct tcpflags
{
    u_int16_t        flags1;
    u_int16_t        flags2;
}tcpflags_t;


static tcpflags_t tcpflagslist[] = {
    { TCP_FLAGS_ALL                  ,  TCP_FLAGS_SYN                                                                 },
    { TCP_FLAGS_FIN | TCP_FLAGS_SYN  ,  TCP_FLAGS_FIN | TCP_FLAGS_SYN                                                 },
    { TCP_FLAGS_SYN | TCP_FLAGS_RST  ,  TCP_FLAGS_SYN | TCP_FLAGS_RST                                                 },
    { TCP_FLAGS_FIN | TCP_FLAGS_RST  ,  TCP_FLAGS_FIN | TCP_FLAGS_RST                                                 },
    { TCP_FLAGS_FIN | TCP_FLAGS_ACK  ,  TCP_FLAGS_FIN                                                                 },
    { TCP_FLAGS_ACK | TCP_FLAGS_URG  ,  TCP_FLAGS_URG                                                                 },
    { TCP_FLAGS_ACK | TCP_FLAGS_FIN  ,  TCP_FLAGS_FIN                                                                 },
    { TCP_FLAGS_ACK | TCP_FLAGS_PSH  ,  TCP_FLAGS_PSH                                                                 },
    { TCP_FLAGS_ALL                  ,  TCP_FLAGS_ALL                                                                 },
    { TCP_FLAGS_ALL                  ,  TCP_FLAGS_NONE                                                                },
    { TCP_FLAGS_ALL                  ,  TCP_FLAGS_FIN | TCP_FLAGS_PSH | TCP_FLAGS_URG                                 },
    { TCP_FLAGS_ALL                  ,  TCP_FLAGS_SYN | TCP_FLAGS_FIN | TCP_FLAGS_PSH | TCP_FLAGS_URG                 },
    { TCP_FLAGS_ALL                  ,  TCP_FLAGS_SYN | TCP_FLAGS_RST | TCP_FLAGS_ACK | TCP_FLAGS_FIN | TCP_FLAGS_URG },

    { 0, 0 },
};


static bool match_tcp_flags(u_int16_t flags)
{
    tcpflags_t *ptr = tcpflagslist;

    while (ptr->flags1 != 0)
    {
        if (((flags & ptr->flags1) ^ ptr->flags2) == 0)
        {
            return true;
        }
        
        ptr ++;
    }

    return false;
}


static bool xt_protection_match(const struct sk_buff *skb,struct xt_action_param *param)
{
    const struct xt_protection_info *info = param->matchinfo;
    const struct iphdr *iph = ip_hdr(skb);
    const struct tcphdr *tcph = NULL;

    u_int16_t plen = 0;
    u_int16_t flags = 0;

    switch (info->type)
    {
        case PROTECTION_TYPE_LAND:
            if (iph->saddr == iph->daddr && iph->saddr != 16777343)
            {
                return 1;
            }
            break;
        case PROTECTION_TYPE_ICMP_BIG:
            if (iph->protocol != 1)
            {
                return 0;
            }

            /* 简单的操作(实际需要根据五元组hash) */
            if (ntohs(iph->frag_off) & 0x2000)
            {
                plen += ntohs(iph->tot_len) - (iph->ihl * 4);
            }
            else
            {
                plen += ntohs(iph->tot_len) - (iph->ihl * 4);

                if (plen >= info->min_pktsize && plen <= info->max_pktsize)
                {
                    return 1;
                }
            }

            break;
        case PROTECTION_TYPE_TCP_SCAN:
            if (iph->protocol != 6)
            {
                return 0;
            }

            tcph = tcp_hdr(skb);

            flags = tcph->fin | tcph->syn | tcph->urg | tcph->ack | tcph->rst | tcph->psh | (tcph->res1 & 0x01);
            
            if (match_tcp_flags(flags))
            {
                return 1;
            }
            break;
    }

    return 0;
}

static struct xt_match xt_protection_mt_reg __read_mostly = {
    .name                    = "protection",
    .family                  = AF_INET,
    .match                   = xt_protection_match,
    .matchsize               = sizeof(struct xt_protection_info),
    .destroy                 = NULL,
    .me                      = THIS_MODULE,    
};


static int __init xt_protection_mt_init(void)
{
    return xt_register_match(&xt_protection_mt_reg);
}


static void __exit xt_protection_mt_fini(void)
{
    xt_unregister_match(&xt_protection_mt_reg);
}


module_init(xt_protection_mt_init);
module_exit(xt_protection_mt_fini);
```

## 用户态程序

```c++
/*
 * @Author: jankincai
 * @Date:   2021-03-09 17:34:54
 * @Last Modified by:   jankincai
 * @Last Modified time: 2021-03-12 00:12:30
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/version.h>
#include <xtables.h>
#include <linux/kernel.h>
#include "ipt_protection.h"


enum {
    O_PROTECTION_TYPE = 0,
    O_PROTECTION_LENGTH,
};


struct value_string
{
    const char             *ptr;
};


static const struct value_string protection_type_map[] = {
    { NULL },
    { "land" },
    { "tcp_scan" },
    { "icmp_big" },
};


/* 旧接口 */
// static struct option xt_protection_opts[] = {
//     { "protection-type", required_argument,       NULL,       '1' },
//     { NULL,              0,                       NULL,        0  },
// };


#define s struct xt_protection_info
static const struct xt_option_entry xt_protection_opts2[] = {
    { .name = "protection-type", .id = O_PROTECTION_TYPE, .type = XTTYPE_STRING, .flags = XTOPT_MAND, .min = 1 },
    { .name = "protection-length", .id = O_PROTECTION_LENGTH, .type = XTTYPE_UINT16RC, .flags = XTOPT_INVERT },

    XTOPT_TABLEEND,
};
#undef s


static void xt_protection_help(void)
{
    printf(
    "protection v%s options:\n"
    " --protection-type type                     Match protection type:\n"
    "                                                 land\n"
    "                                                 icmp_big\n"
    "                                                 tcp_scan\n"
    " --protection-length length[:length]        Match packet length against value or range of values (inclusive)\n"
    "\n"
    "\nExamples:\n"
    " iptables -A FORWARD -m protection --protection-type land -j DROP\n"
    " iptables -A FORWARD -m protection --protection-type icmp_big --protection-length 4000: -j DROP\n"
    , PROTECTION_VERSION);
}


static void xt_protection_init(struct xt_entry_match *m)
{
    // struct xt_protection_info *info = (struct xt_protection_info*)m->data;
}


struct xt_protection_names
{
    const char           *name;
    unsigned int          type;
};


static const struct xt_protection_names xt_protection_names[] = 
{
    { "land",                  PROTECTION_TYPE_LAND     },
    { "icmp_big",              PROTECTION_TYPE_ICMP_BIG },
    { "tcp_scan",              PROTECTION_TYPE_TCP_SCAN },
};


static void xt_protection_parse2(struct xt_option_call *cb)
{
	struct xt_protection_info *info = cb->data;

	xtables_option_parse(cb);

    switch (cb->entry->id)
    {
        case O_PROTECTION_TYPE:
            for (size_t i = 0; i < arraysize(xt_protection_names); i++)
            {
                if (strcasecmp(cb->arg, xt_protection_names[i].name) == 0)
                {
                    info->type = xt_protection_names[i].type;
                    break;
                }
            }

            if (info->type == 0)
            {
                xtables_error(PARAMETER_PROBLEM, "cannot parse --protection-type %s", cb->arg);
            }

            info->flags |= PROTECTION_FLAGS_TYPE;

            break;
        case O_PROTECTION_LENGTH:
            info->min_pktsize = cb->val.u16_range[0];
            info->max_pktsize = cb->val.u16_range[0];
            info->invert = cb->invert;

            if (cb->nvals >= 2)
            {
                info->max_pktsize = cb->val.u16_range[1];
            }

            info->flags |= PROTECTION_FLAGS_LENGTH;
            break;
    }
}


/* 旧接口 */
// static int xt_protection_parse(int c, char **argv, int invert, unsigned int *flags,
//                                const void *entry , struct xt_entry_match **match)
// {
//    struct xt_protection_info *info = (struct xt_protection_info *)(*match)->data;

//    int status = 1;

//    switch(c)
//    {
//         case '1':

//             if (strcasecmp(optarg, "land") == 0)
//             {
//                 info->type = PROTECTION_TYPE_LAND;
//             }
//             else if (strcasecmp(optarg, "icmp_big") == 0)
//             {
//                 info->type = PROTECTION_TYPE_ICMP_BIG;
//             }
//             else if (strcasecmp(optarg, "tcp_scan") == 0)
//             {
//                 info->type = PROTECTION_TYPE_TCP_SCAN;
//             }
//             else
//             {
//                 xtables_error(PARAMETER_PROBLEM, "cannot parse --protection-type %s", optarg);
//                 status = 0;
//             }

//             if (status)
//             {
//                 *flags |= O_PROTECTION_TYPE;
//             }
//         break;
            
//    }

//    return status;
// }


static void xt_protection_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    const struct xt_protection_info *info = (const struct xt_protection_info *)match->data;

    if (info->flags & PROTECTION_FLAGS_TYPE)
    {
        printf(" type %s", protection_type_map[info->type].ptr);
    }
    
    if (info->flags & PROTECTION_FLAGS_LENGTH)
    {
        printf(" length %d:%d", info->min_pktsize, info->max_pktsize);
    }
}


static void xt_protection_save(const void *ip, const struct xt_entry_match *match)
{
    const struct xt_protection_info *info = (const struct xt_protection_info *)match->data;

    if (info->flags & PROTECTION_FLAGS_TYPE)
    {
        printf(" --protection-type %s", protection_type_map[info->type].ptr);
    }
    
    if (info->flags & PROTECTION_FLAGS_LENGTH)
    {
        printf(" --protection-length %d:%d", info->min_pktsize, info->max_pktsize);
    }
}


// static void xt_protection_final_check(unsigned int flags)
// {
//     if (!(flags & O_PROTECTION_TYPE))
//     {
//         xtables_error(PARAMETER_PROBLEM, "must set --protection-type option for protection match module");
//     }
// }


static struct xtables_match xt_protection_mt_reg = {
    .name                      = "protection",
    .version                   = XTABLES_VERSION,
    .family                    = NFPROTO_IPV4,
    .size                      = XT_ALIGN(sizeof(struct xt_protection_info)),
    .userspacesize             = XT_ALIGN(sizeof(struct xt_protection_info)),
    .help                      = xt_protection_help,
    .init                      = xt_protection_init, 
    .print                     = xt_protection_print,
    .save                      = xt_protection_save,

    /* 旧接口 */
    // .parse                     = xt_protection_parse,
    // .final_check               = xt_protection_final_check,
    // .extra_opts                = xt_protection_opts,

    /* 新接口 */
    .x6_parse                  = xt_protection_parse2,
    .x6_options                = xt_protection_opts2,
};


void _init(void)
{
    xtables_register_match(&xt_protection_mt_reg);
}
```

> Makefile

```makefile
# @Author: JanKinCai
# @Date:   2020-11-23 15:24:14
# @Last Modified by:   jankincai
# @Last Modified time: 2021-03-09 18:27:47
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
obj-m += ipt_protection.o

all: ipt_protection.h ipt_protection.c
	make -C ${KERNEL_DIR} M=$$PWD;
	make libipt_protection.so
install: libipt_protection.so ipt_protection.ko
	sudo apt-mark hold linux-image-generic linux-headers-generic
	cp ./libipt_protection.so /usr/lib/x86_64-linux-gnu/xtables
	cp ./ipt_protection.ko /lib/modules/`uname -r`/kernel/net/netfilter/
	depmod -a

	sudo modprobe -i ipt_protection
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
libipt_protection.so: libipt_protection.o
	gcc -shared -fPIC -o $@ $^;
libipt_protection.o: libipt_protection.c
	gcc -O2 -Wall -D_INIT=lib$*_init -fPIC -c -o $@ $<;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf libipt_protection.so libipt_protection.o
uninstall:
	rmmod ipt_protection
	rm /usr/lib/x86_64-linux-gnu/xtables/libipt_protection.so
	rm /lib/modules/`uname -r`/kernel/net/netfilter/ipt_protection.ko
```

> 使用

```bash
sudo iptables -A INPUT -p tcp --syn -m protection --protection-type land -j DROP

sudo iptables -A INPUT -p icmp -m protection --protection-type icmp_big --protection-length 4000: -j DROP

sudo iptables -A INPUT -p tcp -m limit --limit 1000/sec --limit-burst 1000 -m protection --protection-type tcp_scan -j RETURN
sudo iptables -A INPUT -p tcp -m protection --protection-type tcp_scan -j DROP
```
