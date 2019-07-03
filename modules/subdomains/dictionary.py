#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import threading
import dns.resolver
import dns.reversename
import dns.zone
import dns.exception
import dns.rdatatype
import dns.rdata
import socket
import re
import hashlib
from random import random


class MethodDictionary(object):

    def __init__(self, context, dictionaryPath, title):

        # El contexto principal
        self.context = context

        # Mensaje de cabecera personalizado
        self.title = title

        # Contexto del método actual
        self.dictionary = {
            'threads'             : [],
            'max-threads'         : 100,
            'file-handler'        : None,
            'file-path'           : dictionaryPath,
            'nameservers'         : [
                # Mientra mas lento (menos hilos de proceso), el reultado es más
                # efectivo.
                
                # Sin servidores NS personalizados la búsqueda es mas rápida
                # pero puede tener más errores debido a la no fiabilidad del
                # servicio del proveedor de Internet. Use de 500 a 1000 threads.

                # APNIC NS, Cloudflare.
                # Use 200 hilos de proceso como máximo. Estos servidores
                # contienen muchos errores y con mucha frecuencia, arroja muchos
                # falsos positivos. No es recomendado.
                # '1.1.1.1', '1.0.0.1',

                # Google NS.
                # Use 100 hilos de proceso como máximo, en caso contrario el
                # servidor podría arrojar errores debido a que internamente crea
                # una cola de respuesta la cual puede ser muy inestable y
                # provocar desconexiones por tiempo de espera.
                # Con 100 hilos de proceso es muy estable, sin falsos positivos.
                '8.8.8.8', '8.8.4.4'
            ],
            'n-subdomains-in-file': 0,
            'current-line'        : 0,
            'retries'             : 0,
            'max-retries'         : 2,
            'hostname-base'       : None
        }

        # Tiempo de espera por defecto para el módulo del socket
        socket.setdefaulttimeout = 0.50
        

    def find(self):

        # Mensaje de la cabecera del método
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.title
            }
        )

        # Nombre de dominio principal como contexto global para todos los hilos
        # de proceso.
        self.dictionary['hostname-base'] = self.context.baseHostname

        # Detecta si el dominio contiene comodines que impiden la diferenciación
        # de resultados con subdominios inexistentes.
        if(self.haveWildcard()):
            self.context.out(
                self.context.strings['methods']['dictionary']['wildcard-detected']
            )
            return

        self.context.out(
            self.context.strings['methods']['dictionary']['counting-items']
        )

        # Cuenta la cantidad de subdominios totales en el archivo (líneas)
        fileHandler = open(self.dictionary['file-path'], 'r')
        while True:
            # Por bloques grandes pero no exagerados
            b = fileHandler.read(65536)
            if not b:
                fileHandler.close()
                break
            self.dictionary['n-subdomains-in-file'] += b.count('\n')

        # Agrega la línea del primer item
        if(self.dictionary['n-subdomains-in-file'] > 0):
            self.dictionary['n-subdomains-in-file'] += 1

        # Mensaje de cabecera con el total de subdominios a buscar
        self.context.out(
            self.context.strings['methods']['dictionary']['total-items'],
            parseDict={
                'total-items': "{:,}".format(self.dictionary['n-subdomains-in-file'])
            }
        )

        # Puntero del archivo de lectura del diccionario
        self.dictionary['file-handler'] = open(self.dictionary['file-path'], 'r')

        self.context.out(
            self.context.strings['methods']['dictionary']['loading-threads']
        )

        # Crea un espacio para el buffer de salida del progreso
        # https://invisible-island.net/xterm/ctlseqs/ctlseqs.html
        self.context.out(
            self.context.strings['methods']['dictionary']['progress-pre']
        )

        # Crea los hilos de proceso
        while True:

            # Puntero del hilo de proceso
            threadHandler = threading.Thread(target=self.threadCheck)

            # Previene la impresión de mensajes de error al final del hilo
            # principal cuando se cancela el progreso con Conrol+C.
            threadHandler.setDaemon(True)

            # Agrega el puntero a la pila de punteros locales
            self.dictionary['threads'].append(threadHandler)

            # Limitador de hilos de proceso
            if(len(self.dictionary['threads']) >= self.dictionary['max-threads']):
                break

        # Ejecuta todos los hilos de proceso
        for threadHandler in self.dictionary['threads']:
            threadHandler.start()

        # Espera a que todos los hilos finalicen
        for threadHandler in self.dictionary['threads']:

            # Hasta este punto de la ejecución cabe la posibilidad de que el
            # hilo de proceso ya haya finalizado, si se une con join() producirá
            # un error de continuidad haciendo que nunca pueda finalizar.
            if(not threadHandler.is_alive()):
                continue

            threadHandler.join()

        # Limpia el buffer del último estado del progreso de la búsqueda
        self.context.out(
            self.context.strings['methods']['dictionary']['progress-clear']
        )


    def haveWildcard(self):

        # Crea un subdominio ficticio a modo de hash MD5 para detectar si el
        # dominio principal tiene un comodín como subdominio.

        m = hashlib.md5()
        m.update((str(random()) + 'fake').encode('utf-8', 'ignore'))
        fakeSubdomain = '__' + m.hexdigest() + '__.' + self.dictionary['hostname-base']

        useWilcard = None

        try:
            resolv = dns.resolver.Resolver()

            if(self.dictionary['nameservers']):
                resolv.nameservers = self.dictionary['nameservers']

            useWilcard = resolv.query(fakeSubdomain, 'A', tcp=True)
            
        except Exception as e:
            pass

        return useWilcard


    def threadCheck(self):

        # Hilo de proceso que busca y valida subdominios
        while(True):

            subdomain = None

            try:
                # Intenta obtener la siguiente línea del diccionario
                subdomain = self.dictionary['file-handler'].readline().strip().lower()

                # Aumenta el número de la línea actual (para imprimir el
                # progreso).
                self.dictionary['current-line'] += 1

            except Exception as e:
                pass

            if(not subdomain):
                # No hay mas líneas.
                break

            # Compone el nombre de dominio completo a buscar
            hostname = subdomain.strip() + '.' + self.dictionary['hostname-base']

            # Cantidad de reintentos actuales
            retries  = 0

            # Iteración de intentos
            while(True):

                # Informa el progreso actual
                self.context.out(
                    message=(
                        self.context.strings['methods']['dictionary']['progress-clear'] +
                        '\n'.join(self.context.strings['methods']['dictionary']['progress'])
                    ),
                    parseDict={
                        'hostname'      : hostname,
                        'current-line'  : "{:,}".format(self.dictionary['current-line']),
                        'total-lines'   : "{:,}".format(self.dictionary['n-subdomains-in-file']),
                        'percent-lines' : "{:,.2f}".format(((self.dictionary['current-line'] * 100) / self.dictionary['n-subdomains-in-file'])) + '%',
                        'total-threads' : self.dictionary['max-threads'],
                        'total-retries' : self.dictionary['retries']
                    },
                    end=''
                )

                # Si el nombre de dominio tiene una dirección IP válida es 
                # porque existe.

                nsAnswer = None
                try:

                    resolv = dns.resolver.Resolver()

                    if(self.dictionary['nameservers']):
                        resolv.nameservers = self.dictionary['nameservers']

                    # Crea una consulta DNS al registro A
                    nsAnswer = resolv.query(hostname, 'A', tcp=True)

                    if(not nsAnswer):
                        # No hay una dirección IP asociada al nombre de dominio
                        break

                    # Busca en cada respuesta del registro A
                    for rdata in nsAnswer:

                        # Intenta obtener la dirección IP de la respuesta
                        ip = rdata.to_text().strip('"')
                        if(not ip):
                            # No hay una dirección IP asociada a la respuesta
                            continue

                        # Agrega el subdominio encontrado a la pila global de
                        # resultados.
                        self.context.addHostName(
                            hostname=hostname,
                            messageFormat=(

                                # Clear space of the buffer rogress
                                self.context.strings['methods']['dictionary']['progress-clear'] +

                                # Show the subdomain found
                                self.context.strings['methods']['dictionary']['item-found'] +

                                # Make space for the buffer progress
                                self.context.strings['methods']['dictionary']['progress-pre']
                            )
                        )

                        # Detiene la búsqueda en las respuestas de la consulta
                        # DNS.
                        break

                    # Detiene el while, no hay reintentos, todo está bien
                    break

                except dns.resolver.NXDOMAIN:
                    # No se encuentra el nombre de dominio
                    break

                except dns.resolver.Timeout:
                    # Hay que reintentar otra vez

                    # Actualiza el contador de reintentos para el nombre de 
                    # dominio actual.
                    retries += 1

                    # Actualiza el contador de reintentos globales
                    self.dictionary['retries'] += 1

                    # ¿Se ha llegado al límite de reintentos?
                    if(retries > self.dictionary['max-retries']):
                        break

                except dns.exception.DNSException:
                    # Error desconocido
                    break

                except Exception as e:
                    # Error desconocido
                    break