#ifndef __IPT_TEST_H__
#define __IPT_TEST_H__

#define USER_PORT                100
#define NETLINK_TEST             30

#define TEST_FLAGS_TARGET          0x01
#define TEST_FLAGS_ID              0x02

#define DIRECTION_REQ                            0x00
#define DIRECTION_RESP                           0x01
#define DIRECTION_UNKNOWN                        0x02

/* Target */
enum target_type {
    TARGET_ALERT=1,
    TARGET_DROP,
    TARGET_REJECT,
    TARGET_ACCEPT,
    TARGET_LOG,
};

struct pktinfo {
    __u8                        dire; /* 数据包方向 */

    __be32                     saddr;
    __be32                     daddr;
    __be16                     sport;
    __be16                     dport;
    __be16                   tot_len;
    unsigned char          h_dest[6];
    unsigned char        h_source[6];
    __u8                    protocol;
    __u32                       mark;

    __u8                      target; /* 处理动作 */
    __u32                         id; /* ID */
};

struct ipt_test_info {
    unsigned char          target; /* Target */
    unsigned int               id; /* ID */
};

#endif /* __IPT_TEST_H__ */
