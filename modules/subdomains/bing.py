#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.crawler import WCrawler


class MethodBing:

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
                'title'   : self.context.strings['methods']['bing']['title']
            }
        )

        # Busca en la primera página
        self.paginate()


    def paginate(self, pageNumber=1):

        # Contexto de la búsqueda de la página actual
        searchContext = {
            'max-pages'   : 15,
            'max-result'  : 10,
            'start-index' : 1,
            'query'       : 'domain:' + self.context.baseHostname
        }

        # ¿Hay resultados del método actual?
        if(self.hostnames):
            
            # Excluye los subdominios ya conocidos
            searchContext['query'] += (
                ' -domain:' +
                ' -domain:'.join(self.hostnames)
            )

        # Número del resultado de inicio actual
        searchContext['start-index'] = (
            ((pageNumber - 1) * searchContext['max-result']) + 1
        )

        # Header message for pagination
        self.context.out(
            message=self.context.strings['methods']['bing']['pagination']
        )

        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None

        try:
            result = crawler.httpRequest(
                'https://www.bing.com/search?' +
                '&q='     + crawler.urlencode(searchContext['query']) +
                '&first=' + str(searchContext['start-index'])
            )

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['bing']['no-connect']
            )
            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['bing']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Busca cada nombre de dominio
        # Ejemplo de resultados: <cite>https://foo<strong>ejemplo.com</strong>
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(self.context.baseHostname).encode() + br')',
            result['response-content'].replace(
                b'<strong>' + self.context.baseHostname.encode(),
                b'.' + self.context.baseHostname.encode()
            )
        )

        if(len(matches) == 0):
            # No hay resultados
            self.context.out(
                self.context.strings['methods']['bing']['no-more-results']
            )
            return

        # Procesa cada nombre de dominio encontrado
        for item in matches:

            # ¿El resultado es un subdominio inválido?
            if(not item.decode().endswith('.' + self.context.baseHostname)):
                continue

            # Evita los resultados duplicados utilizando la pila local
            if(item.decode() in self.hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            self.hostnames.append(item.decode())

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=item.decode(),
                messageFormat=self.context.strings['methods']['bing']['item-found']
            )

        # ¿Hay mas páginas donde buscar?
        if(not b'sw_next' in result['response-content']):
            self.context.out(
                self.context.strings['methods']['bing']['no-more-results']
            )
            return
            
        # Límite de busqueda de páginas
        if(pageNumber >= searchContext['max-pages']):
            self.context.out(
                self.context.strings['methods']['bing']['no-more-results']
            )
            return

        # Continua con la siguiente página
        self.paginate(pageNumber=pageNumber + 1)