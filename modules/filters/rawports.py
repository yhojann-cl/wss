#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import datetime
import time
from ipaddress import IPv4Address, IPv4Network
from IPy import IP

from modules.helpers.networking.raw import Interface
from modules.helpers.networking.raw import Ethernet
from modules.helpers.networking.raw import TCP
from modules.helpers.networking.raw import IPv4
from modules.helpers.networking.raw import TCPHelper


class FilterRawPorts(object):

    def __init__(self, context):

        # El contexto principal
        self.context = context

        # 10.0.0.0\8
        self.classA = IPv4Network(('10.0.0.0', '255.0.0.0'))

        # 172.16.0.0\12
        self.classB = IPv4Network(('172.16.0.0', '255.240.0.0'))

        # 192.168.0.0\16
        self.classC = IPv4Network(('192.168.0.0', '255.255.0.0'))

        # Direcciones IP que se está buscando actualmente, para recibir desde el
        # sniffer.
        self.remoteIpAddressStack = [ ]

        # Indica si los hilos de proceso pueden continuar o deben detenerse
        self.canContinue = True

        # Cantidad de tiempo de espera máximo para detener la búsqueda después
        # del último evento de la búsqueda de puertos.
        self.maxSecondsTimeout = 10

        # Puntero del socket a escucha (para el forzado de la detención del hilo
        # de proceso cuando no hay paquetes de ningún tipo).
        self.socketHandlerBind = None


    def filterAll(self):
        
        # Cabecera del mensaje del filtro actual
        self.context.out(
            message=self.context.strings['filter-begin'],
            parseDict={
                'current' : self.context.progress['filters']['current'],
                'total'   : self.context.progress['filters']['total'],
                'title'   : self.context.strings['filters']['raw-ports']['title']
            }
        )

        # Direcciones IP que se está buscando actualmente, para recibir desde el
        # sniffer.
        self.remoteIpAddressStack = self.context.results['ip-address']['items'].keys()

        # Corre el sniffer en busca de los paquetes de respuesta de puertos
        threadHandler = threading.Thread(target=self.sniffer)

        # Previene la impresión de mensajes de error al final del hilo
        # principal cuando se cancela el progreso con Conrol+C.
        threadHandler.setDaemon(True)

        # Ejecuta el hilo de proceso
        threadHandler.start()

        # Procesa cada dirección IP
        ipAddressNumber = 0
        for ipAddress in self.context.results['ip-address']['items'].keys():

            ipAddressNumber += 1

            # Crea la estructura del objeto de la dirección IP y sus puertos
            if(ipAddress != 'unknown'):
                self.context.results['ip-address']['items'][ipAddress]['items']['ports'] = {
                    'title' : self.context.strings['filters']['raw-ports']['node-tree']['ports-title'],
                    'items' : { }
                }

            # Realiza la búsqueda de puertos
            self.findPorts(ipAddress, ipAddressNumber)

            if(ipAddress == 'unknown'):
                # No necesita esperar
                continue

            self.context.out(
                self.context.strings['filters']['raw-ports']['progress-wait']
            )

            # Iteración cada x segundos
            time.sleep(self.maxSecondsTimeout)

        self.canContinue = False
        self.socketHandlerBind.close()

        # Espera a que finalice el hilo de proceso del sniffer.
        threadHandler.join()


    def findPorts(self, ipAddress, ipAddressNumber):

        self.context.out(
            message=self.context.strings['filters']['raw-ports']['find'],
            parseDict={
                'address': ipAddress,
                'current': ipAddressNumber,
                'total'  : len(self.context.results['ip-address']['items'].keys())
            }
        )

        # Solo busca en direcciones IP existentes
        if(ipAddress == 'unknown'):
            self.context.out(
                self.context.strings['filters']['raw-ports']['unknown-skip']
            )
            return

        # Omite los rangos locales
        # TODO: Puede ser requerido para pentesting.
        if(IP(ipAddress).iptype() in ['PRIVATE', 'LOOPBACK']):
            self.context.out(
                self.context.strings['filters']['raw-ports']['skip']
            )
            return

        # if(address in self.classA):
        #     pass

        interface = Interface()
        tcpHelper = TCPHelper()

        # Dirección IP local donde llegarán los paquetes
        localIpAddress = interface.getSourceAddress()

        # Rango de puertos a revisar
        for port in range(1, 65535):

            self.context.out(
                message=(
                    self.context.strings['filters']['raw-ports']['progress-clear'] +
                    self.context.strings['filters']['raw-ports']['progress']
                ),
                parseDict={
                    'source' : ipAddress,
                    'target' : localIpAddress,
                    'port': port
                },
                end=''
            )

            # Envía un paquete syn a modo de señuelo mientras que el hilo de
            # proceso del socket a escucha está listo para recibir las
            # respuestas.
            try:
                tcpHelper.sendSyn(
                    sourceIp=localIpAddress,
                    toAddress=ipAddress,
                    dstPort=port
                )
            except Exception as e:
                # Ok, puede suceder, es normal
                pass
        
        # Ordena el resultado de los puertos encontrados
        self.context.results['ip-address']['items'][ipAddress]['items']['ports']['items'] = (
            { k: v for k, v in sorted(self.context.results['ip-address']['items'][ipAddress]['items']['ports']['items'].items()) }
        )

        # Limpia el buffer del último estado del progreso de la búsqueda
        self.context.out(
            message=self.context.strings['filters']['raw-ports']['progress-clear'],
            end=''
        )

    
    def sniffer(self):

        interface = Interface()

        # Dirección IP local donde llegarán los paquetes
        localIpAddress = interface.getSourceAddress()

        # Puntero del socket a escucha
        self.socketHandlerBind = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(3) # 3 = ETH_P_ALL
        )

        # Comnfigura el tamaño del buffer del socket (evita largas colas)
        self.socketHandlerBind.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            212992
        )

        # Pone a escucha el socket
        # (ifname, proto [,pkttype [,hatype]])
        self.socketHandlerBind.bind((interface.getDefaultInterface(), 3))

        # Tamaño de bloques de paquetes por defecto
        mtu = 65535

        while self.canContinue:

            # Recibe los paquetes desde la interfaz de red por defecto
            try:
                rawData, addr = self.socketHandlerBind.recvfrom(mtu)
            except Exception as e:
                # Error de recepción de datos o finalización del tiempo de
                # espera y forzado del cierre del socket.
                continue

            eth = Ethernet(rawData)

            # ¿Es IPv4?
            if(not eth.isIpV4()):
                continue

            ipv4 = IPv4(eth.data)

            # ¿Es TCP?
            if(not ipv4.isTCP()):
                continue

            tcp = TCP(ipv4.data)

            # Se necesita el paquete que viene desde la ip remota hacia la ip
            # local.
            if(
                (not ipv4.target == localIpAddress) or
                (not ipv4.src in self.remoteIpAddressStack)
            ):
                continue

            # SYN-ACK (puerto abierto)
            if(tcp.flagSyn and tcp.flagAck):

                # Reescribe el progreso actual utilizando el mensaje de resultados
                self.context.out(
                    message=(
                        self.context.strings['filters']['raw-ports']['progress-clear'] +
                        self.context.strings['filters']['raw-ports']['found'] + '\n' +
                        self.context.strings['filters']['raw-ports']['progress-wait']
                    ),
                    parseDict={
                        'source' : ipv4.src,
                        'target' : ipv4.target,
                        'port'   : tcp.srcPort
                    },
                    end=''
                )

                # Agrega el puerto a la pila principal de resultados
                # Como objeto: Para facilitar el acceso a todas sus propiedades
                #              y extensión del diccionario en otros filtros.
                self.context.results['ip-address']['items'][ipv4.src]['items']['ports']['items'][tcp.srcPort] = None