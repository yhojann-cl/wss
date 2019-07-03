#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os.path
import json
import argparse
import pytz
import locale
import socket
from   datetime         import datetime
from   anytree          import Node, RenderTree
from   anytree.importer import DictImporter

# Módulos buscadores de subdominios
from modules.subdomains.axfr               import MethodAxfr
from modules.subdomains.dnsqueries         import MethodDnsQueries
from modules.subdomains.virustotal         import MethodVirusTotal
from modules.subdomains.robtex             import MethodRobtex
from modules.subdomains.crtsh              import MethodCrtSh
from modules.subdomains.certificatedetails import MethodCertificateDetails
from modules.subdomains.google             import MethodGoogle
from modules.subdomains.bing               import MethodBing
from modules.subdomains.dnsdumpster        import MethodDnsDumpster
from modules.subdomains.dictionary         import MethodDictionary

# Filtros
from modules.filters.ports                 import FilterPorts
from modules.filters.http                  import FilterHttpServices


# Clase del controlador principal
class Controller(object):

    def __init__(self):

        # Obtiene el lenguaje actual del Sistema Operativo
        currentLocale = locale.getdefaultlocale()[0].split('_')[0].lower()

        # Obtiene el archivo de textos correspondiente al lenguaje actual si 
        # existe.
        langFilePath = 'resources/strings/' + str(currentLocale) + '.json'
        if(not os.path.isfile(langFilePath)):
            langFilePath = 'resources/strings/en.json'

        # Carga el archivo de textos
        with open(langFilePath, 'r') as fileHandler:
            self.strings = json.load(fileHandler)

        # Python 3 es requerido
        if sys.version_info < (3, 0):
            print(self.strings['errors']['bad-python-version'])
            exit(1)

        self.version = {
            'major'   : 2,
            'minor'   : 4,
            'patch'   : 9,
            'release' : 'beta'
        }

        # Nombre de dominio principal a procesar
        self.baseHostname = None

        # Estructura del diccionario de resultados:
        # {
        #     "ip-address": {
        #         "items": {
        #             "x.x.x.x": {
        #                 "items": {
        #                     "hostnames": {
        #                         "items": {
        #                             "www.example.com": null
        #                         },
        #                         "title": "Hostnames"
        #                     },
        #                     "ports": {
        #                         "items": [
        #                             80
        #                         ],
        #                         "title": "Ports"
        #                     }
        #                 },
        #                 "title": "x.x.x.x"
        #             },
        #             "unknown": {
        #                 "items": {
        #                     "hostnames": {
        #                         "items": {
        #                             "foo.example.com": null,
        #                             "bar.example.com": null
        #                         },
        #                         "title": "Hostnames"
        #                     }
        #                 },
        #                 "title": "Unknown IP address"
        #             }
        #         },
        #         "title": "3 hosts were found"
        #     }
        # }
        # Puedes modificar y agregar items al arbol de resultados, estos se
        # mostrarán de manera automática siempre y cuando no rompa la estructura
        # principal.
        self.results = {
            'ip-address': {
                'title': self.parseString(
                    message=self.strings['result']['node-tree']['root'],
                    parseDict={
                        'count': 0
                    }
                ),
                'items': { }
            }
        }

        # Pila de métodos en orden
        self.methods = [ ]

        # Pila de filtros en orden
        self.filters = [ ]

        # Estado actual del progreso en general
        self.progress = {
            'methods' : {
                'current' : 0,
                'total'   : 0
            },
            'filters': {
                'current' : 0,
                'total'   : 0
            },
            'total-hostnames' : 0
        }

        # Cabecera principal del mensaje de la línea de comandos
        self.out(
            message=self.strings['header'],
            parseDict={
                'version': (
                    str(self.version['major']) + '.' +
                    str(self.version['minor']) + '.' +
                    str(self.version['patch']) + '-' +
                    str(self.version['release'])
                )
            }
        )
        
        # Obtiene todos los argumentos procesables desde la línea de comandos
        argparseHandler = argparse.ArgumentParser(
            add_help=False
        )

        argparseHandler.add_argument(
            '-h',
            '--help',
            dest='help',
            action='store_true'
        )

        argparseHandler.add_argument(
            '--host',
            dest='hostname',
            nargs='?'
        )

        argparseHandler.add_argument(
            '-m',
            '--methods',
            dest='methods',
            nargs='?'
        )

        argparseHandler.add_argument(
            '-f',
            '--filters',
            dest='filters',
            nargs='?'
        )

        # Procesa todos los argumentos
        arguments, unknownArguments = argparseHandler.parse_known_args(
            sys.argv[1:]
        )

        # El nombre de dominio principal es requerido, sino ¿qué buscaremos?
        if(not arguments.hostname):
            return self.help()

        # Establece el nombre de dominio como contexto global
        self.baseHostname = arguments.hostname

        # ¿Hay métodos?
        if(not arguments.methods):

            # Métodos por defecto
            arguments.methods = '0123456789a'

        # Procesa cada método (es cada caracter)
        for methodId in arguments.methods:

            if(methodId == '0'):
                self.methods.append(MethodAxfr(self))

            elif(methodId == '1'):
                self.methods.append(MethodDnsQueries(self))

            elif(methodId == '2'):
                self.methods.append(MethodVirusTotal(self))

            elif(methodId == '3'):
                self.methods.append(MethodRobtex(self))

            elif(methodId == '4'):
                self.methods.append(MethodCrtSh(self))

            elif(methodId == '5'):
                self.methods.append(MethodCertificateDetails(self))

            elif(methodId == '6'):
                self.methods.append(MethodGoogle(self))

            elif(methodId == '7'):
                self.methods.append(MethodBing(self))

            elif(methodId == '8'):
                self.methods.append(MethodDnsDumpster(self))

            elif(methodId == '9'):
                self.methods.append(MethodDictionary(
                    self,
                    'resources/dictionaries/dict-brute-4.txt',
                    self.strings['methods']['dictionary-4']['title']
                ))

            elif(methodId == 'a'):
                self.methods.append(MethodDictionary(
                    self,
                    'resources/dictionaries/dict-subdomains.txt',
                    self.strings['methods']['dictionary-words']['title']
                ))

            else:
                self.out(
                    message=self.strings['errors']['unknown-method'],
                    parseDict={
                        'method': methodId
                    }
                )
                self.out('') # Espacio separador
                self.help()
                return

        # ¿Hay métodos después de haber procesado incluso los por defecto?
        if(len(self.methods) == 0):

            # No hay métodos, probablemente se estableció el argumento de
            # métodos sin valores, por ejemplo: -m ''
            self.out(self.strings['errors']['empty-methods'])
            return

        # ¿Hay filtros?
        if(
            (arguments.filters is not None) and
            (len(arguments.filters) > 0)
        ):

            # Procesa cada filtro (es cada catacrer)
            for filterId in arguments.filters:

                if(filterId == '0'):
                    self.filters.append(FilterPorts(self))

                elif(filterId == '1'):
                    self.filters.append(FilterHttpServices(self))

                else:
                    self.out(
                        message=self.strings['errors']['unknown-filter'],
                        parseDict={
                            'filter': filterId
                        }
                    )
                    self.out('') # Espacio separador
                    self.help()
                    return

        self.progress['methods']['total'] = len(self.methods)
        self.progress['filters']['total'] = len(self.filters)

        # Ejecuta todos los métodos en el mismo orden en que fueron establecidos
        self.processAllMethods()

        # ¿Hay resultados?
        if(len(self.results.keys()) == 0):

            # No hay resultados
            self.out(self.strings['result']['empty'])
            return

        # Ordena todo el diccionario de resultados por dirección IP
        self.results['ip-address']['items'] = (
            { k: v for k, v in sorted(self.results['ip-address']['items'].items()) }
        )

        # Ordena todos los nombres de dominio (subdominios) encontrados por cada
        # dirección IP.
        for ipAddress in self.results['ip-address']['items'].keys():
            self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'] = (
                { k: v for k, v in sorted(self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'].items()) }
            )

        # Ejecuta todos los filtros en el mismo orden en que fueron establecidos
        self.processAllFilters()

        # Muestra todos los resultados
        self.showResulsts()


    def processAllMethods(self):

        # ¿Hay métodos a procesar?
        if(len(self.methods) == 0):

            # No hay métodos a procesar
            return

        # Varable que define si es posible continuar con el siguiente método,
        # por ejemplo si una consulta AXFR obtiene todos los subdominios
        # existentes no será necesario continuar con el resto de los métodos.
        self.canContinue = True

        # Procesa cada método
        for methodClass in self.methods:

            # Incrementa el número del método actual
            self.progress['methods']['current'] += 1

            # Busca subdominios en el método actual
            methodClass.find()

            # Libera la memoria destruyendo la clase, de esta manera también es
            # ejecutado el destructor de manera inmediata para posibles
            # ordenamientos o pos procesamientos.
            # Recordar que existen métodos con pilas locales de subdominios
            # encontrados para evitar mostrar resultados duplicados y estas
            # pilas utilizan buena parte del espacio en la memoria RAM.
            methodClass = None

            self.out('') # Espacio separador

            # ¿Puede continuar?
            if(not self.canContinue):

                # No puede continuar
                break

    
    def processAllFilters(self):

        # ¿Hay filtros a procesar?
        if(len(self.filters) == 0):

            # No hay filtros a procesar
            return

        # Varable que define si es posible continuar con el siguiente filtro
        self.canContinue = True

        # Procesa cada filtro
        for filterClass in self.filters:

            # Incrementa el número del filtro actual
            self.progress['filters']['current'] += 1

            # Filtra todos los resultados utilizando el filtro actual
            filterClass.filterAll()

            # Libera la memoria destruyendo la clase, de esta manera también es
            # ejecutado el destructor de manera inmediata para posibles
            # ordenamientos o pos procesamientos.
            filterClass = None

            self.out('') # Espacio separador

            # ¿Puede continuar?
            if(not self.canContinue):

                # No puede continuar
                break


    def showResulsts(self):

        # Crea el formato de fecha para el archivo a guardar
        dt = datetime.utcnow().replace(tzinfo=pytz.utc).strftime('[%Y-%m-%d %H_%M_%S]')
        saveLogPath = 'subdomains_' + self.baseHostname + '_' + dt + '.log'

        # Mensaje de cabecera del resultado final
        self.out(self.strings['result']['result-all-title'])

        # Actualiza el título del mensaje de resultados
        self.results['ip-address']['title'] = self.parseString(
            message=self.strings['result']['node-tree']['root'],
            parseDict={
                'count': self.progress['total-hostnames']
            }
        )

        # Crea el nodo raíz del arbol de resultados
        nodeRoot = self.makeNodes(self.results['ip-address'])

        # Mensaje con el arbol de resultados que será reutilizado en el mensaje
        # por consola y el archivo de resultados.
        message = []

        # Crea el contenido del arbol de resultados
        for pre, fill, node in RenderTree(nodeRoot):
            message.append(
                self.parseString(
                    message=self.strings['result']['node-tree']['item-printed'],
                    parseDict={
                        'item': pre + str(node.name).strip()
                    }
                )
            )

        # Muestra el arbol de resultados
        self.out('\n'.join(message))

        self.out('') # Espacio separador

        # Mensaje de cabecera del guardado del archivo de resultados
        self.out(
            message=self.strings['log-file']['saving'],
            parseDict={
                'path': saveLogPath
            }
        )

        # Guarda el arbol de resultados en el archivo
        fileHandler = open(saveLogPath, 'w') 
        fileHandler.write('\n'.join(message))
        fileHandler.close()

        # Libera la memoria del arbol de resultados
        message = None

        # Muestra final
        self.out(self.strings['result']['finish'])


    def makeNodes(self, data, parent=None):

        if(parent is None):
            # Nodo raíz
            root = Node(data['title'])
        else:
            # Rama del nodo
            root = Node(data['title'], parent=parent)

        # ¿Hay items?
        if(len(data['items'].keys()) == 0):

            # No hay más items
            return root

        for itemKey, itemValue in data['items'].items():
            if(
                isinstance(itemValue, dict) and
                ('title' in itemValue)
            ):
                # tiene item 'title' por lo cual es una rama
                self.makeNodes(itemValue, parent=root)

            else:
                # No tiene nodo 'title' por lo cual es un nodo final
                Node(str(itemKey), root)

        # Retorna el nodo raíz
        return root


    def parseString(self, message, parseDict=None):

        # ¿Mensaje multilínea?
        if(isinstance(message, list)):
            message = '\n'.join(message)

        # ¿Mensaje con múltiples valores a procesar?
        if(
            (parseDict) and
            isinstance(parseDict, dict)
        ):
            # Procesa cada item del diccionario de valores
            for key, value in parseDict.items():

                # Cada llave es representada con llaves foraneas
                message = str(message).replace('{' + str(key) + '}', str(value))

        # Retorna el mensaje final (puede ser de varios tipos pero debe retornar
        # siempre un string a modo de representación).
        return str(message)


    def out(self, message, parseDict=None, end='\n'):

        # Imprime el mensaje
        print(
            self.parseString(message, parseDict),
            end=end,
            flush=True
        )


    def addHostName(self, hostname, messageFormat=None):

        # Elimina el comodin del subdominio
        if(hostname.startswith('*.')):
            hostname = hostname[2:]

        # Evita procesar el nombre de dominio principal (talves debido a un
        # comodín como subdominio).
        if(hostname == self.baseHostname):
            return

        # Obtiene la dirección IP del subdominio encontrado
        ipAddress = None
        try:
            ipAddress = str(socket.gethostbyname(hostname))

        except Exception as e:
            # Valor por defecto cuando no existe
            ipAddress = 'unknown'

        # ¿La dirección IP ya existía?, eso quiere decir que ya existe la
        # estructura del diccionario.
        if(not ipAddress in self.results['ip-address']['items']):

            # Crea la estructura del nuevo objeto de la nueva dirección IP encontrada
            self.results['ip-address']['items'][ipAddress] = {
                'title' : (self.strings['result']['unknown-ip-address-key'] if ipAddress == 'unknown' else ipAddress),
                'items' : {
                    'hostnames': {
                        'title' : self.strings['result']['node-tree']['hostnames-title'],
                        'items' : { }
                    }
                }
            }
        
        # ¿El subdominio existe en el diccionario de resultados de la dirección IP?
        if(not hostname in self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items']):

            # Agrega el subdominio al objeto de la dirección IP (para facilitar
            # el acceso a sus datos desde otros módulos).
            self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'][hostname] = None

            # Incrementa el progreso de subdominios encontrados
            self.progress['total-hostnames'] += 1

        # ¿Modo silencioso? (sin salida en la línea de comandos)
        if(messageFormat is None):
            return

        # Imprime el mensaje del progreso actual del subdominio encontrado
        self.out(
            message=messageFormat,
            parseDict={
                'hostname'   : hostname,
                'ip-address' : (self.strings['result']['unknown-ip-address-key'] if ipAddress == 'unknown' else ipAddress)
            }
        )

        
    def help(self):

        # Imprime el mensaje de ayuda
        self.out(
            message=self.strings['usage'],
            parseDict={
                'scriptname': str(sys.argv[0])
            }
        )


if __name__ == '__main__':
    try:
        controllerCls = Controller()

    except (KeyboardInterrupt, SystemExit):

        # Posiciona el puntero de la línea de comandos en una línea limpia
        print('')

        # Salida con estado normal
        exit(0)
