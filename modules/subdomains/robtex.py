#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.crawler import WCrawler


class MethodRobtex:

    def __init__(self, context):

        # El contexto principal
        self.context = context


    def find(self):

        # Mensaje de la cabecera del método
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['robtex']['title']
            }
        )

        # Uso del crawler
        crawler = WCrawler()
        crawler.defaultTimeout = 30

        # Resultado de tipo HTML
        result = None

        try:
            result = crawler.httpRequest(
                url='https://www.robtex.com/dns-lookup/' + crawler.urlencode(self.context.baseHostname)
            )

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:

            # Imposible navegar
            self.context.out(
                self.context.strings['methods']['robtex']['no-connect']
            )

            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['robtex']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Elimina las etiquetas de negritas del resultado: foo.<b>domain.com</b>
        result['response-content'] = result['response-content'].replace(
            b'<b>', b''
        ).replace(
            b'</b>', b''
        )

        # Busca todos los posibles subdominios
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(self.context.baseHostname).encode() + br')<',
            result['response-content']
        )

        # ¿Hay resultados?
        if(len(matches) == 0):
            self.context.out(
                self.context.strings['methods']['robtex']['empty']
            )
            return

        # Procesa todos los resultados
        for item in matches:

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=item.decode(),
                messageFormat=self.context.strings['methods']['robtex']['item-found']
            )
