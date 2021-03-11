# iptables动态端口

## 模块

| Name of kernel module | port | Name recognized by iptables |
| --- | --- | --- |
| nf_conntrack_amanda | UDP 10080 | amanda |
| nf_conntrack_ftp | TCP 21 | ftp |
| nf_conntrack_h323 | UDP 1719
TCP 1720 | RSA (udp 1719)
Q.931 (tcp 1720) |
| nf_conntrack_irc | TCP 6667 | irc |
| nf_conntrack_netbios_ns | UDP 137 | netbios-ns |
| nf_conntrack_pptp | TCP 1723 | pptp |
| nf_conntrack_sane | TCP 6566 | sane |
| nf_conntrack_sip | UDP 5060 | sip |
| nf_conntrack_snmp | UDP 161 | snmp |
| nf_conntrack_tftp | UDP 69 | tftp |

## FTP

```bash
# INPUT
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
sudo iptables -A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -m helper --helper ftp -j ACCEPT
sudo iptables -A PREROUTING -t raw -p tcp --dport 21 -j CT --helper ftp

# FORWARD
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -p tcp --dport 21 -j ACCEPT
sudo iptables -A FORWARD -p tcp --sport 21 -j ACCEPT
sudo iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -m helper --helper ftp -j ACCEPT
sudo iptables -A PREROUTING -t raw -p tcp --dport 21 -j CT --helper ftp
```

## TFTP

```bash
# INPUT
# FORWARD
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -p tcp --dport 69 -j ACCEPT
sudo iptables -A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -m helper --helper tftp -j ACCEPT
sudo iptables -t raw -I PREROUTING -p udp --dport 69 -j CT --helper tftp

# FORWARD
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -p tcp --dport 69 -j ACCEPT
sudo iptables -A FORWARD -p tcp --sport 69 -j ACCEPT
sudo iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -m helper --helper tftp -j ACCEPT
sudo iptables -t raw -I PREROUTING -p udp --dport 69 -j CT --helper tftp
```

## 链接

- [Netfilter Helpers](https://shorewall.org/Helpers.html)
