# WSS v2.5.2-beta

[![Chileno](https://img.shields.io/badge/From-Chile-blue.svg)](https://es.wikipedia.org/wiki/Chile)
[![Licencia](https://img.shields.io/badge/license-GPL%20(%3E%3D%202)-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Contribuciones](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/WHK102/wss/issues)
[![Donaciones](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/whk102)

WSS (WHK Subdomains Scanner) es una herramienta diseñada para **pentesters**, la
cual realiza búsqueda de subdominios y realiza acciones sobre cada nombre de
dominio encontrado.

La aplicación funciona con dos grupos de módulos:

- Métodos de búsqueda de subdominios.
- Filtros.

Los **filtros** son módulos que procesan los resultados para añadir más
información como por ejemplo el barrido básico de puertos y la búsqueda de
servicios *http*.


## Requerimientos

- Python 3.
- Google API-Key en `modules/subdomains/google.py` (opcional, por defecto viene
  una de regalo).
- Instalación de los módulos declarados en `requirements.txt` utilizando pip3.

Nota: Se han reportado problemas de codificación de caracteres utilizando
Microsoft Windows, por ello se recomienda por el momento que buscamos una
solución, utilizar alguna distribución de GNU/Linux ya que se respeta mejor
la codificación de los archivos.


## Instalación

No es necesario una instalación en el Sistema Operativo, basta con la
instalación de los módulos requeridos en `requirements.txt` para funcionar.

Los requrimientos se pueden instalar de la siguiente manera:

    pip3 install --user -r requirements.txt


## Uso

Vamos al grano:

    $ python3 wss.py --help
    WSS (WHK Subdomains Scanner)
    Versión  : v2.5.2-beta
    Contacto : whk@elhacker.net
    -----------------------------------------
       
    Uso: wss.py [opciones]
       
    Resultado: Un arbol de nombres de dominio (subdominios) encontrados 
    agrupados por dirección IP.
       
    Opciones:
      -h, --help     Muestra el mensaje de ayuda.
          --host     El nombre de dominio a buscar.
      -m, --methods  Listado de métodos.
                     Métodos disponibles:
                       0: Consulta DNS/AXFR.
                       1: Consultas DNS a registros comunes (TXT, MX, SPF, etc).
                       2: Busca en virustotal.com.
                       3: Busca en robtex.com.
                       4: Busca en crt.sh.
                       5: Busca en certificatedetails.com.
                       6: Busca en google.com (si tiene la api-key).
                       7: Busca en bing.com.
                       8: Busca en dnsdumpster.com.
                       9: Fuerza bruta de 4 caracteres.
                       a: Utiliza un dictionario de subdominios conocidos.
                     Ejemplos:
                       -m 01
                       -m 49a
                       -m 0123456789a
                     Por defecto se utilizan todos los métodos disponibles.
      -f, --filters  Listado de filtros.
                     Filtros disponibles:
                       0: Busca puertos abiertos por cada dirección IP utilizando
                          sockets a bajo nivel (SYN-ACK), muy veloz pero necesita
                          privilegios, solo requiere de 3 threads.
                       1: Busca puertos abiertos por cada dirección IP. La búsqueda
                          es básica, no reemplaza a un software convencional como
                          nmap. Utiliza por defecto 500 threads. No necesita
                          privilegios pero es un método muy lento.
                       2: Busca servicios HTTP en los puertos encontrados por el
                          filtro 0, en caso contrario utilizará un listado de
                          puertos http conocidos. Utiliza por defecto 20 threads.
                     Ejemplos:
                       -f 0
                       -f 02
                     Por defecto no se utiliza ningún filtro.
       
    Ejemplos:
      wss.py --host starbucks.com -f 2
      sudo wss.py --host starbucks.com -f 02
      sudo wss.py --host dev.starbucks.com -f 02

Puedes intentar una prueba rápida:

    sudo python3 wss.py --host elhacker.net -m 4 -f 02

Un ejemplo del resultado final de una búsqueda:

    4 subdominios encontrados
        ├── x.x.x.x
        │   ├── Hostnames
        │   │   ├── ssh.ejemplo.com
        │   │   └── www.ejemplo.com
        │   │       └── Servicios HTTP
        │   │           └── http://www.ejemplo.com/ (HTTP-200: Ejemplo WEB)
        │   └── Ports
        │       ├── 22
        │       └── 80
        └── Direcciones IP desconocidas
            └── Hostnames
                ├── foo.ejemplo.com
                └── bar.ejemplo.com
    

## Lenguaje

Los archivos de traducciones y textos se encuentran en el directorio
`resources/strings/*.json` donde cada nombre de archivo es igual al código iso
del lenguaje.

La aplicación detectará el lenguaje utilizado por defecto en el Sistema
Operativo y buscará el archivo correspondiente de traducción, si no existe
utilizará el lenguaje por defecto `en.json`.


## Ventajas

Además de buscar en los servicios públicos ya conocidos, puede usar la fuerza
bruta obteniendo subdominios nuevos sin utilizar bases de datos. También
proporciona un árbol de direcciones IP asociadas para conocer subdominios
redundantes, lo que ahorra tiempo en la revisión de los servicio.

La aplicación cuenta con una separación modular de los métodos y filtrados,
facilitando la creación de nuevos módulos personalizados.


## Probado en

- Ubuntu 18.04.2 LTS
- CentOS 7
- Debian 9
- Kali 2019.2
