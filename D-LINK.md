## D-LINK DIR 850L
D-Link DIR 850L无线AC1200双频千兆云路由器的10个漏洞，来自于[Pwning the Dlink 850L routers and abusing the MyDlink Cloud protocol](https://pierrekim.github.io/blog/2017-09-08-dlink-850l-mydlink-cloud-0days-vulnerabilities.html)

### “固件”防护
Dlink 850L最新的固件Dlink 850L revA(DIR850L_REVA_FW114WWb07_h2ab_beta1.bin)没有被保护，攻击者可以简单的伪造新的固件映像

最新的固件映像Dlink 850L revB(DIR850LB1_FW207WWb05.bin, DIR850L_REVB_FW207WWb05_h1ke_beta1.bin, DIR850LB1 FW208WWb02.bin)使用硬编码的密码保护

代码**_revbdec.c_**可以用于解密固件映像

程序的使用方法如下：

```
user@kali:~/petage-dlink$ ./revbdec DIR850L_REVB_FW207WWb05_h1ke_beta1.bin wrgac25_dlink.2013gui_dir850l > DIR850L_REVB_FW207WWb05_h1ke_beta1.decrypted
user@kali:~/petage-dlink$ binwalk DIR850L_REVB_FW207WWb05_h1ke_beta1.decrypted

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             DLOB firmware header, boot partition: "dev=/dev/mtdblock/1"
593           0x251           LZMA compressed data, properties: 0x88, dictionary size: 1048576 bytes, uncompressed size: 65535 bytes
10380         0x288C          LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5184868 bytes
1704052       0x1A0074        PackImg section delimiter tag, little endian size: 10518016 bytes; big endian size: 8298496 bytes
1704084       0x1A0094        Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8296266 bytes, 2678 inodes, blocksize: 131072 bytes, created: 2017-01-20 06:39:29
```

固件映像的保护是不存在的


### WAN && LAN - revA - XSS
D-Link 850L RevA的LAN口和WAN口都对数个简单的跨站脚本(XSS)漏洞束手无策

通过简单分析_/htdocs/web_中的PHP文件，可以发现几个XSS。

>攻击者可以使用XSS来定向已认证的用户，以便窃取身份验证cookie。


### WAN && LAN - revB
D-Link 850L RevB的LAN口和WAN口同样脆弱。攻击者可以检索管理员口令，使用MyDLink云协议，来将设备添加到攻击者账户，取得对该路由器的完全访问权。

链接里给出了详细的攻击场景

### 弱云协议影响D-Link 850L RevA和RevB
D-Link不仅用MyDLink服务以明文存储所有设备的口令，连其TCP中继系统都没有用任何加密来保护用户和MyDLink之间的通信。

MyDLink界面允许用户输入Gmail账户之类的凭证，这“看起来可不是个好主意，因为该路由器和云平台之间的流量没有加密，或者只是用缺乏验证的自签名证书加密，且口令也是用互联网通过这个渠道发送。

### LAN - revB 后门访问
用提供的口令登录Alphanetworks，就会使攻击者获得设备的 root shell。仅用于LAN侧

### WAN && LAN - revA and revB 密钥硬编码
秘密私钥被硬编码在 D-Link 850L RevA和RevB 的固件中，令中间人攻击成为可能。

### WAN && LAN - revA - DNS配置的Nonce爆破

 _htdocs/parentalcontrols/bind.php_ 允许修改DNS配置，不进行身份认证

攻击者可以爆破nonce（?nonce=integer），HTTP请求没有限制，也没有认证方法

```
  8 $uptime_limit = query(INF_getinfpath($WAN1)."/open_dns/nonce_uptime") + 1800;
  9 if(query(INF_getinfpath($WAN1)."/open_dns/nonce")!=$_GET["nonce"] || $_GET["nonce"]=="")
 10 {
 11         $Response="BindError";
 12 }
 13 else if(query("/runtime/device/uptime") > $uptime_limit)
 14 {
 15         $Response="BindTimeout";
 16 }
```

然后攻击者可以定义新的DNS服务器
```
 21         set(INF_getinfpath($WAN1)."/open_dns/deviceid", $_GET["deviceid"]);
 22         set(INF_getinfpath($WAN1)."/open_dns/parent_dns_srv/dns1", $_GET["dnsip1"]);
 23         set(INF_getinfpath($WAN1)."/open_dns/parent_dns_srv/dns2", $_GET["dnsip2"]);
```

### 本地文件被暴露，弱文件权限和明文存储凭证

#### /var/passwd

 _/var/passwd_ 明文存储凭证，权限是：-rw-rw-rw-(666)


```
# ls -la /var/passwd
-rw-rw-rw-    1 root     root           28 Jan  1 00:00 /var/passwd
# cat /var/passwd
"Admin" "password" "0"
```

#### /var/etc/hnapasswd

攻击者可以使用 _/var/etc/hnapasswd_ 获取明文密码

```
# cat /var/etc/hnapasswd
Admin:password
```

 _/var/etc/hnapasswd_ 的权限也是-rw-rw-rw-(666)
```
# ls -la /var/etc/hnapasswd
-rw-rw-rw-    1 root     root           20 Jan  1 00:00 /var/etc/hnapasswd
```

#### /etc/shadow

 _/etc/shadow/_ 是 _/var/etc/passwd_ 的符号链接, _/var/etc/passwd_ 是所有人可读的，如下：

```
# ls -al /etc/shadow 
lrwxrwxrwx    1 root     root           15 Jan 20  2017 /etc/shadow -> /var/etc/shadow
# ls -la /var/etc/shadow
-rw-r--r--    1 root     root           93 Jan  1 00:00 /var/etc/shadow
```

这个文件包含一个admin用户的DES哈希

```
# cat /var/etc/shadow
root:!:10956:0:99999:7:::
nobody:!:10956:0:99999:7:::
Admin:zVc1PPVw2VWMc:10956:0:99999:7:::
```

#### /var/run/storage_account_root

 _/var/run/storage_account_root_ 包含明文的凭证，文件权限是-rw-rw-rw-(666)

```
# ls -la /var/run/storage_account_root
-rw-rw-rw-    1 root     root           40 Jan  1 00:00 /var/run/storage_account_root
# cat /var/run/storage_account_root
admin:password,:::
jean-claude:dusse,:::
```

#### /var/run/hostapd*

 _/var/run/hostapd*_ 包含明文的无线密码，文件的权限是：-rw-rw-rw-(666)

```
# ls -la /var/run/hostapd*
-rw-rw-rw-    1 root     root           73 Jan  1 00:00 /var/run/hostapd-wlan1wps.eap_user
-rw-rw-rw-    1 root     root         1160 Jan  1 00:00 /var/run/hostapd-wlan1.conf
-rw-rw-rw-    1 root     root           73 Jan  1 00:00 /var/run/hostapd-wlan0wps.eap_user
-rw-rw-rw-    1 root     root         1170 Jan  1 00:00 /var/run/hostapd-wlan0.conf
# cat /var/run/hostapd*|grep -i pass
wpa_passphrase=aaaaa00000
wpa_passphrase=aaaaa00000
```

###  WAN - revB - Pre-Auth RCEs as root (L2)
路由器上的DHCP客户端可能遭受造成root权限的命令注入攻击

通过路由器内运行的DHCP服务器，该攻击可被传递至内部客户端。所以，如果你连接一台脆弱D-Link路由器到你的内部网络，整个网络都会被黑

### LAN - revA and revB -某些守护进程可能遭受DOS
