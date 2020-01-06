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
from resources.util.helpers import Helper


class FilterRawPorts(object):
    def __init__(self):

        # Direcciones IP que se está buscando actualmente, para recibir desde el
        # sniffer.
        self.remoteIpAddressStack = []

        # Indica si los hilos de proceso pueden continuar o deben detenerse
        self.canContinue = True

        # Puntero del socket a escucha (para el forzado de la detención del hilo
        # de proceso cuando no hay paquetes de ningún tipo).
        self.socketHandlerBind = None

        self.result = []

    def filter(self, address):
        h = Helper()
        # Direcciones IP que se está buscando actualmente, para recibir desde el
        # sniffer.
        self.remoteIpAddressStack = h.resolve_dns(address)

        # Corre el sniffer en busca de los paquetes de respuesta de puertos
        threadHandler = threading.Thread(target=self.sniffer)

        # Previene la impresión de mensajes de error al final del hilo
        # principal cuando se cancela el progreso con Conrol+C.
        threadHandler.setDaemon(True)

        # Ejecuta el hilo de proceso
        threadHandler.start()

        for ip in self.remoteIpAddressStack:

            # Realiza la búsqueda de puertos
            self.findPorts(address)

            # Iteración cada x segundos
            time.sleep(10)

        self.canContinue = False
        self.socketHandlerBind.close()

        # Espera a que finalice el hilo de proceso del sniffer.
        threadHandler.join()

        return self.result

    def findPorts(self, address):
        h = Helper()
        # Omite los rangos locales
        # TODO: Puede ser requerido para pentesting.
        if h.ip_validate(address) is not None:
            if (IP(address).iptype() in ['PRIVATE', 'LOOPBACK']):
                return

        interface = Interface()
        tcpHelper = TCPHelper()

        # Dirección IP local donde llegarán los paquetes
        localIpAddress = interface.getSourceAddress()

        # Rango de puertos a revisar
        for port in range(1, 65535):
            # Envía un paquete syn a modo de señuelo mientras que el hilo de
            # proceso del socket a escucha está listo para recibir las
            # respuestas.
            try:
                tcpHelper.sendSyn(sourceIp=localIpAddress,
                                  toAddress=address,
                                  dstPort=port)
            except Exception as e:
                # Ok, puede suceder, es normal.
                # Por alguna extraña razón el socket en cierto punto arroja un
                # acceso denegado indicando que no tengo permisos para la
                # operación a pesar de tener privilegios elevados, pero de todas
                # maneras el paquete se envía sin problemas.
                pass

    def sniffer(self):

        interface = Interface()

        # Dirección IP local donde llegarán los paquetes
        localIpAddress = interface.getSourceAddress()

        # Puntero del socket a escucha
        self.socketHandlerBind = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(3)  # 3 = ETH_P_ALL
        )

        # Configura el tamaño del buffer del socket (evita largas colas)
        self.socketHandlerBind.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                          212992)

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
                continue

            eth = Ethernet(rawData)

            if not eth.isIpV4():
                continue

            ipv4 = IPv4(eth.data)

            if not ipv4.isTCP():
                continue

            # SYN-ACK (puerto abierto)
            tcp = TCP(ipv4.data)

            if ((tcp.flagSyn) or (tcp.flagAck)):
                data = {
                    'source': ipv4.src,
                    'target': ipv4.target,
                    'port': tcp.srcPort,
                    'mac': eth.getRemoteMac()
                }
                self.result.append(data)