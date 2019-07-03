#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
from ipaddress import IPv4Address, IPv4Network
from IPy import IP

from modules.helpers.crawler import WCrawler


class FilterPorts(object):

    def __init__(self, context):

        # El contexto principal
        self.context = context

        # 10.0.0.0\8
        self.classA = IPv4Network(('10.0.0.0', '255.0.0.0'))

        # 172.16.0.0\12
        self.classB = IPv4Network(('172.16.0.0', '255.240.0.0'))

        # 192.168.0.0\16
        self.classC = IPv4Network(('192.168.0.0', '255.255.0.0'))

        # Contexto del nombre de dominio
        self.hostnameContext = {
            'check-ports'        : [ ],
            'ports-found'        : { },
            'threads-handlers'   : [ ],
            'current-ip-address' : None
        }


    def filterAll(self):
        
        # Cabecera del mensaje del filtro actual
        self.context.out(
            message=self.context.strings['filter-begin'],
            parseDict={
                'current' : self.context.progress['filters']['current'],
                'total'   : self.context.progress['filters']['total'],
                'title'   : self.context.strings['filters']['ports']['title']
            }
        )

        # Procesa cada dirección IP
        itemNumber = 0
        for ipAddress in self.context.results['ip-address']['items'].keys():

            itemNumber += 1

            if(ipAddress == 'unknown'):
                continue

            # Crea la estructura del objeto de la dirección IP y sus puertos
            self.context.results['ip-address']['items'][ipAddress]['items']['ports'] = {
                'title' : self.context.strings['filters']['ports']['node-tree']['ports-title'],
                'items' : self.findPorts(ipAddress, itemNumber)
            }


    def findPorts(self, ipAddress, itemNumber):

        self.context.out(
            message=self.context.strings['filters']['ports']['find'],
            parseDict={
                'address': ipAddress,
                'current': itemNumber,
                'total'  : len(self.context.results['ip-address']['items'].keys())
            }
        )

        # Omite los rangos locales
        # TODO: Puede ser requerido para pentesting.
        if(IP(ipAddress).iptype() in ['PRIVATE', 'LOOPBACK']):
            self.context.out(
                self.context.strings['filters']['ports']['skip']
            )
            return []

        # if(address in self.classA):
        #     pass

        # Contexto del nombre de dominio (para múltiples hilos de proceso)
        self.hostnameContext['check-ports']        = list(reversed(range(1, 65535)))
        self.hostnameContext['ports-found']        = { }
        self.hostnameContext['threads-handlers']   = [ ]
        self.hostnameContext['current-ip-address'] = ipAddress

        # 1024 hilos por defecto
        for threadNumber in range(1, 1024):

            # Puntero del hilo de proceso
            threadHandler = threading.Thread(target=self.threadCheck)

            # Previene la impresión de mensajes de error al final del hilo
            # principal cuando se cancela el progreso con Conrol+C.
            threadHandler.setDaemon(True)

            # Agrega el puntero a la pila de punteros locales
            self.hostnameContext['threads-handlers'].append(threadHandler)

        # Ejecuta todos los hilos de proceso
        for threadHandler in self.hostnameContext['threads-handlers']:
            threadHandler.start()

        # Espera a que todos los hilos finalicen
        for threadHandler in self.hostnameContext['threads-handlers']:

            # Hasta este punto de la ejecución cabe la posibilidad de que el
            # hilo de proceso ya haya finalizado, si se une con join() producirá
            # un error de continuidad haciendo que nunca pueda finalizar.
            if(not threadHandler.is_alive()):
                continue

            threadHandler.join()

        # Limpia el buffer del último estado del progreso de la búsqueda
        self.context.out(
            message=self.context.strings['filters']['ports']['progress-clear'],
            end=''
        )

        # Ordena el resultado de los puertos encontrados y lo retorna
        return { k: v for k, v in sorted(self.hostnameContext['ports-found'].items()) }


    def threadCheck(self):

        while(True):
        
            if(len(self.hostnameContext['check-ports']) == 0):
                # No hay mas puertos a buscar
                break

            # Obtiene el siguiente puerto a buscar
            port = int(self.hostnameContext['check-ports'].pop())

            self.context.out(
                message=(
                    self.context.strings['filters']['ports']['progress-clear'] +
                    self.context.strings['filters']['ports']['progress']
                ),
                parseDict={
                    'port': port
                },
                end=''
            )

            isOpen = False

            try:
                socketHandler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socketHandler.settimeout(7) # Tiempo máximo de espera en segundos
                socketHandler.connect((
                    self.hostnameContext['current-ip-address'],
                    port
                ))
                socketHandler.shutdown(1)
                socketHandler.close()

                isOpen = True

            except Exception as e:
                pass

            if(isOpen):

                # Reescribe el progreso actual utilizando el mensaje de resultados
                self.context.out(
                    message=(
                        self.context.strings['filters']['ports']['progress-clear'] +
                        self.context.strings['filters']['ports']['found'] + '\n' +
                        self.context.strings['filters']['ports']['progress-wait']
                    ),
                    parseDict={
                        'port'  : port
                    },
                    end=''
                )

                # Agrega el puerto a la pila principal de resultados
                # Como objeto: Para facilitar el acceso a todas sus propiedades
                #              y extensión del diccionario en otros filtros.
                self.hostnameContext['ports-found'][port] = None