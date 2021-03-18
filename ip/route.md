# route

## 命令

```bash
# 设置路由表信息
# cat /etc/iproute2/rt_tables

# 查看所有路由表
ip rule list

#显示指定路由表信息
ip route list table local

# 查看cache
ip route show cache

# 清空路由表101
ip route flush table 101
# 立即生效
ip route flush cache
```

## 默认路由表

```bash
# cat /etc/iproute2/rt_tables

255       local          # 本地路由表存有本地接口地址，广播地址，以及NAT地址
                         # 系统自动维护，管理员不能操作

254        main          # 主路由表，传统路由表，ip route没有指定操作表

253       default        # 默认路由表
```

## 高级路由

```bash
# 显示路由规则
ip rule show

# 路由规则添加(如果不指定pref，则将在已有规则最小序号前插入)
# 创建完路由规则立即生效ip route flush cache
#    from -- 源地址
#    to   -- 目的地址
#    tos  -- ip头的TOS
#    dev  -- 物理接口
#    fwmark -- iptables标签
ip rule add table 1
ip rule add from 192.168.1.10/32 table 1 pref 100
```

- 添加路由

```bash
ip route add 192.168.166.0/24 via 192.168.0.1

# 指定表名
ip route add 192.168.166.0/24 via 192.168.0.1 table jkc12

# 类似
route add -net 192.168.166.0/24 gw 192.168.0.1
```

- 追加路由

```bash
#追加一个指定网络的路由，为了平滑切换网关使用
ip route append 192.168.166.0/24 via 10.0.0.1
```

- 修改路由

```bash
```

- 删除路由

```base

```