#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
from ipaddress import IPv4Address, IPv4Network
from IPy import IP


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

        # Cola de puertos a revisar por dirección IP
        self.portsStack = [ ]


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
        ipAddressNumber = 0
        for ipAddress in self.context.results['ip-address']['items'].keys():

            ipAddressNumber += 1

            # Solo busca en direcciones IP existentes
            if(ipAddress == 'unknown'):
                continue

            # Crea la estructura del objeto de la dirección IP y sus puertos
            self.context.results['ip-address']['items'][ipAddress]['items']['ports'] = {
                'title' : self.context.strings['filters']['ports']['node-tree']['ports-title'],
                'items' : { }
            }

            # Realiza la búsqueda de puertos
            self.findPorts(ipAddress, ipAddressNumber)


    def findPorts(self, ipAddress, ipAddressNumber):

        self.context.out(
            message=self.context.strings['filters']['ports']['find'],
            parseDict={
                'address': ipAddress,
                'current': ipAddressNumber,
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

        # Rango de puertos a revisar
        self.portsStack = list(reversed(range(1, 65535)))

        # Punteros de los hilos de proceso
        threadsHandlers = [ ]

        # Linux por defecto soporta 1024 threads a menos que se modifique
        # los límites en /etc/security/limits.conf
        # 500 hilos por defecto
        for threadNumber in range(1, 500):

            # Puntero del hilo de proceso
            threadHandler = threading.Thread(
                target=self.threadCheck,
                kwargs={
                    'threadNumber' : threadNumber,
                    'ipAddress'    : ipAddress
                }
            )

            # Previene la impresión de mensajes de error al final del hilo
            # principal cuando se cancela el progreso con Conrol+C.
            threadHandler.setDaemon(True)

            # Ejecuta el hilo de proceso
            threadHandler.start()

            # Obtiene el identificador único del hilo de proceso
            threadsHandlers.append(threadHandler)

        for threadHandler in threadsHandlers:
            
            # Espera a que finalice el hilo de proceso
            threadHandler.join()

        # Ordena el resultado de los puertos encontrados
        self.context.results['ip-address']['items'][ipAddress]['items']['ports']['items'] = (
            { k: v for k, v in sorted(self.context.results['ip-address']['items'][ipAddress]['items']['ports']['items'].items()) }
        )

        # Limpia el buffer del último estado del progreso de la búsqueda
        self.context.out(
            message=self.context.strings['filters']['ports']['progress-clear'],
            end=''
        )


    def threadCheck(self, threadNumber, ipAddress):

        while(True):
        
            try:
                # Obtiene el siguiente puerto a buscar
                port = self.portsStack.pop()

            except Exception as e:
                # No hay más puertos a buscar
                break

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

            socketHandler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketHandler.settimeout(7) # Tiempo máximo de espera en segundos

            try:
                socketHandler.connect((ipAddress, port))
                isOpen = True

            except Exception as e:
                pass

            socketHandler.close()

            # Si el puerto no está abierto no es necesario continuar
            if(not isOpen):
                continue

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
            self.context.results['ip-address']['items'][ipAddress]['items']['ports']['items'][port] = None
