/*
 * @Author: JanKinCai
 * @Date:   2020-11-23 14:19:01
 * @Last Modified by:   jankincai
 * @Last Modified time: 2021-03-18 10:01:13
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/version.h>
#include <xtables.h>
#include "ipt_TEST.h"


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


// https://git.netfilter.org/iptables/tree/include/xtables.h?id=482c6d3731e2681cb4baae835c294840300197e6


static const struct option test_opts[] = {
    { "target",        required_argument,       NULL,       '1' },
    { "id",            required_argument,       NULL,       '2' },
    { NULL,            0,                       NULL,        0  },
};


static void test_help(void)
{
    printf("-j TEST --target DROP --id 1\n");
}


static void test_init(struct xt_entry_target *t)
{
    struct ipt_test_info *info = (struct ipt_test_info*)t->data;

    info->target = TARGET_ACCEPT;
}


/* 旧API，新API请参考iptables自定义match */
static int test_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
    struct ipt_test_info *info = (struct ipt_test_info*)(*target)->data;

    uint32_t val;
    bool status = 0;

    switch (c)
    {
        case '1':
            status = 1;
            if (strcasecmp(optarg, "ALERT") == 0)
            {
                info->target = TARGET_ALERT;
            }
            else if (strcasecmp(optarg, "DROP") == 0)
            {
                info->target = TARGET_DROP;
            }
            else if (strcasecmp(optarg, "REJECT") == 0)
            {
                info->target = TARGET_REJECT;
            }
            else if (strcasecmp(optarg, "ACCEPT") == 0)
            {
                info->target = TARGET_ACCEPT;
            }
            else if (strcasecmp(optarg, "LOG") == 0)
            {
                info->target = TARGET_LOG;
            }
            else
            {
                xtables_error(PARAMETER_PROBLEM, "cannot parse --target '%s", optarg);
                status = 0;
            }

            *flags |= TEST_FLAGS_TARGET;

            break;
        case '2':
            if (!xtables_strtoui(optarg, NULL, &val, 0, UINT32_MAX))
            {
                xtables_error(PARAMETER_PROBLEM, "cannot parse --id '%s", optarg);
            }

            if (val < 0)
            {
                xtables_error(PARAMETER_PROBLEM, "Argument passed to --id cannot be negative");
            }

            info->id = val;
            *flags |= TEST_FLAGS_ID;
            status = 1;
            break;
        default:
            break;
    }

    return status;
}


static void test_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
    const struct ipt_test_info *info = (const struct ipt_test_info*)target->data;

    printf(" target %s ", target_map[info->target].ptr);

   if (info->id != 0)
   {
       printf("id %d ", info->id);
   }
}


static void test_save(const void *ip, const struct xt_entry_target *target)
{
    const struct ipt_test_info *info = (const struct ipt_test_info*)target->data;

    printf(" --target %s ", target_map[info->target].ptr);

   if (info->id != 0)
   {
       printf("--id %d ", info->id);
   }
}


static void test_check(unsigned int flags)
{
    if (!(flags & TEST_FLAGS_TARGET))
    {
        xtables_error(PARAMETER_PROBLEM, "must set --target option for ipt_test target module");
    }
}


static struct xtables_target test_tg_reg = {
    .name               = "TEST",
    .version            = XTABLES_VERSION,
    .family             = NFPROTO_IPV4,
    .size               = XT_ALIGN(sizeof(struct ipt_test_info)),
    .userspacesize      = XT_ALIGN(sizeof(struct ipt_test_info)),
    .help               = test_help,
    .init               = test_init,
    .parse              = test_parse,
    .print              = test_print,
    .save               = test_save,
    .final_check        = test_check,
    .extra_opts         = test_opts,
};


void _init(void)
{
    xtables_register_target(&test_tg_reg);
}
