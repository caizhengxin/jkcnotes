# ipt_TEST

## 安装

```bash
sudo apt-get install xtables-dev

# ipt_TEST
make -j
sudo make install
gcc -g -Wall -o userspace userspace.c 
```

## 使用

```bash
sudo modprobe -i ipt_TEST
sudo iptables -A INPUT -p icmp -j TEST --target DROP --id 1

sudo ./userspace
```

