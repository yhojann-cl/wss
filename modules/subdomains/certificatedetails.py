#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from modules.helpers.networking.crawler import WCrawler


class MethodCertificateDetails:

    def __init__(self, context):

        # El contexto principal
        self.context = context
        
        # Variable que permite entregar subdominios únicos (no duplicados)
        self.hostnames = []


    def find(self):

        # Mensaje de la cabecera del método
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['certificate-details']['title']
            }
        )

        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None

        try:
            result = crawler.httpRequest(
                url='https://certificatedetails.com/api/list/' + crawler.urlencode(self.context.baseHostname)
            )

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['certificate-details']['no-connect']
            )
            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['certificate-details']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        try:
            # Convierte el resultado en un objeto de tipo json
            result = json.loads(result['response-content'])

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['certificate-details']['corrupt-response']
            )
            return

        if(
            (not isinstance(result, list)) or
            (len(result) == 0)
        ):
            self.context.out(
                self.context.strings['methods']['certificate-details']['empty']
            )
            return

        # Procesa cada nombre de dominio encontrado
        for item in result:

            # ¿Es un subdominio válido?
            if(not item['CommonName'].endswith('.' + self.context.baseHostname)):
                continue

            # Evita los resultados duplicados utilizando la pila local
            if(item['CommonName'] in self.hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            self.hostnames.append(item['CommonName'])

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=item['CommonName'],
                messageFormat=self.context.strings['methods']['crt-sh']['item-found']
            )

        # Mensaje de cabecera del comienzo de la obtención de todos los enlaces
        self.context.out(
            self.context.strings['methods']['certificate-details']['find-links']
        )

        # Identificador actual del enlace
        linkId = 0

        # Procesa cada enlace
        # Precaución: Un mismo nombre de dominio repetido puede contener uno o
        #             más certificados diferentes.
        for item in result:

            linkId += 1

            self.findInLink(
                url='https://certificatedetails.com' + item['Link'],
                linkId=linkId,
                totalLinks=len(result)
            )


    def findInLink(self, url, linkId, totalLinks):

        # Mensaje de cabereca de inicio de obtención del enlace
        self.context.out(
            message=self.context.strings['methods']['certificate-details']['find-link'],
            parseDict={
                'link-id'     : linkId,
                'total-links' : totalLinks
            },
            end=''
        )
        
        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo HTML
        result = None

        try:
            result = crawler.httpRequest(url=url)

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['certificate-details']['find-clear'],
                end=''
            )
            return

        self.context.out(
            self.context.strings['methods']['certificate-details']['find-clear'],
            end=''
        )

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            # Nothing
            return

        # Busca todos los posibles subdominios
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(self.context.baseHostname).encode() + br')<',
            result['response-content']
        )

        # ¿Hay resultados?
        if(len(matches) == 0):
            return

        # Procesa cada nombre de dominio
        for item in matches:

            if(
                # Evita los resultados duplicados utilizando la pila local
                (not item.decode() in self.hostnames) and

                # ¿Es un subdominio válido?
                (item.decode().endswith('.' + self.context.baseHostname))
            ):
            
                # Agrega el subdominio encontrado a la pila local
                self.hostnames.append(item.decode())

                # Agrega el subdominio encontrado a la pila global de resultados
                self.context.addHostName(
                    hostname=item.decode(),
                    messageFormat=self.context.strings['methods']['certificate-details']['item-found']
                )
