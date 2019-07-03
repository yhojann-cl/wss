#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from modules.helpers.crawler import WCrawler


class MethodCrtSh:

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
                'title'   : self.context.strings['methods']['crt-sh']['title']
            }
        )

        # Uso del crawler
        crawler = WCrawler()
        crawler.defaultTimeout = 60

        # El resultado es de tipo json
        result = None

        try:
            result = crawler.httpRequest(
                url='https://crt.sh/?q=' + crawler.urlencode('%.' + self.context.baseHostname) + '&output=json'
            )

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['crt-sh']['no-connect']
            )
            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['crt-sh']['wrong-status-http'],
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
                self.context.strings['methods']['crt-sh']['corrupt-response']
            )
            return

        if(
            (not isinstance(result, list)) or
            (len(result) == 0)
        ):
            self.context.out(
                self.context.strings['methods']['crt-sh']['empty']
            )
            return

        # Procesa cada nombre de dominio encontrado
        for item in result:

            # Evita los resultados duplicados utilizando la pila local
            if(item['name_value'] in self.hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            self.hostnames.append(item['name_value'])

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=item['name_value'],
                messageFormat=self.context.strings['methods']['crt-sh']['item-found']
            )
