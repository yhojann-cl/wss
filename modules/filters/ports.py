#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
from ipaddress import IPv4Address, IPv4Network
from resources.util.helpers import Helper
from IPy import IP


class FilterPorts(object):
    def __init__(self):
        self.ports = []
        self.ips = []

    def findPorts(self, ipaddress):
        h = Helper()
        # Omite los rangos locales
        # TODO: Puede ser requerido para pentesting.
        if h.ip_validate(ipaddress) is not None:
            if (IP(ipaddress).iptype() in ['PRIVATE', 'LOOPBACK']):
                return {'ports': []}

        self.ips = h.resolve_dns(ipaddress)
        response = []

        for ip in self.ips:
            if ip == ipaddress:
                continue
            result = {'record': {'ip': []}}
            self.stack = list(reversed(range(1, 65535)))

            result['record']['ip'] = ip
            result['record']['ports'] = []
            # Punteros de los hilos de proceso
            threadsHandlers = []

            # Linux por defecto soporta 1024 threads a menos que se modifique
            # los límites en /etc/security/limits.conf
            # 500 hilos por defecto
            for threadNumber in range(1, 500):
                # Puntero del hilo de proceso
                threadHandler = threading.Thread(target=self.threadCheck,
                                                 kwargs={'ipaddress': ip})
                # Previene la impresión de mensajes de error al final del hilo
                # principal cuando se cancela el progreso con Conrol+C.
                threadHandler.setDaemon(True)
                # Obtiene el identificador único del hilo de proceso
                threadsHandlers.append(threadHandler)
                # Ejecuta el hilo de proceso
                threadHandler.start()

            for threadHandler in threadsHandlers:
                # Espera a que finalice el hilo de proceso
                threadHandler.join()

            result['record']['ports'] = sorted(self.ports)
            response.append(result)
            self.ports = []

        return response

    def threadCheck(self, ipaddress):

        while (True):

            try:
                # Obtiene el siguiente puerto a buscar
                port = self.stack.pop()

            except Exception as e:
                # No hay más puertos a buscar
                break

            isOpen = False

            socketHandler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketHandler.settimeout(7)  # Tiempo máximo de espera en segundos

            try:
                socketHandler.connect((ipaddress, port))
                isOpen = True

            except Exception as e:
                pass

            socketHandler.close()

            # Si el puerto no está abierto no es necesario continuar
            if (not isOpen):
                continue
            #Add open port to list
            self.ports.append(port)