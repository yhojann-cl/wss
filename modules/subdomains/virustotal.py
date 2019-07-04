#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from modules.helpers.networking.crawler import WCrawler


class MethodVirusTotal:

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
                'title'   : self.context.strings['methods']['virus-total']['title']
            }
        )

        # Busca desde la primera página de la api (recursivo)   
        self.findInApi()


    def findInApi(self, nextUrl=None, pageId=1):

        # Mensaje de la paginación
        self.context.out(
            message=self.context.strings['methods']['virus-total']['paginating'],
            parseDict={
                'number': pageId
            }
        )

        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None

        try:
            if(nextUrl is None):
                result = crawler.httpRequest(
                    url='https://www.virustotal.com/ui/domains/' + crawler.urlencode(self.context.baseHostname) + '/subdomains?limit=40'
                )
            else:
                result = crawler.httpRequest(nextUrl)

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:

            # Imposible navegar
            self.context.out(
                self.context.strings['methods']['virus-total']['no-connect']
            )

            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['virus-total']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        try:
            # Convierte el resultado en un objeto de tipo json
            result = json.loads(result['response-content'])

        except Exception as e:

            # Contenido corrupto, no es de tipo json procesable
            self.context.out(
                self.context.strings['methods']['virus-total']['corrupt-response']
            )

            return

        # ¿Hay contenido de la respuesta HTTP?
        if(len(result['data']) == 0):

            # No hay contenido, por lo cual tampoco hay más resultados
            self.context.out(self.context.strings['methods']['virus-total']['no-more'])

            return

        # Procesa todos los subdominios encontrados en la página actual
        for item in result['data']:

            # Evita los resultados duplicados utilizando la pila local
            if(str(item['id']) in self.hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            self.hostnames.append(str(item['id']))

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=str(item['id']),
                messageFormat=self.context.strings['methods']['virus-total']['item-found']
            )

        # ¿Necesita continuar paginando resultados?
        if(
            ('links' in result) and
            ('next' in result['links']) and
            (result['links'])
        ):
            # Continua con la siguiente página
            self.findInApi(
                nextUrl=str(result['links']['next']),
                pageId=(pageId + 1)
            )
