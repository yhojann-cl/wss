#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.crawler import WCrawler


class MethodDnsDumpster(object):

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
                'title'   : self.context.strings['methods']['dnsdumpster']['title']
            }
        )

        # Paso 1: BçObtiene el Token XSRF y mantiene el contexto de navegación
        # para conservar la cookie de sesión.
        self.context.out(
            self.context.strings['methods']['dnsdumpster']['getting-token-xsrf']
        )

        # Uso del crawler, por defecto guardará la cookie de sesión manteniendo
        # el contexto del flujo de la navegación.
        crawler = WCrawler()

        # El resultado es de tipo HTML
        result = None

        try:
            result = crawler.httpRequest(
                url='https://dnsdumpster.com/'
            )

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['dnsdumpster']['no-connect']
            )
            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['dnsdumpster']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Busca el token XSRF
        matches = re.search(
            br'name=\'csrfmiddlewaretoken\'\s+value=\'(.+?)\'',
            result['response-content'],
            re.I | re.M
        )
        
        if(not matches):
            # No se pudo encontrar el token
            self.context.out(
                self.context.strings['methods']['robtex']['no-xsrf-token-found']
            )
            return

        # Guarda el roken XSRF en la variable local para reutilizar la variable
        # 'matches'.
        tokenXsrf = matches.group(1)

        # Paso 2: Envía la solicitud HTTP con el subdominio a buscar
        self.context.out(
            self.context.strings['methods']['dnsdumpster']['getting-subdomains']
        )

        # El resultado es de tipo HTML
        result = None

        try:
            result = crawler.httpRequest(
                url='https://dnsdumpster.com/',
                postData={
                    'csrfmiddlewaretoken' : tokenXsrf,
                    'targetip'            : self.context.baseHostname
                }
            )

        except Exception as e:
            raise e
            self.context.out(
                self.context.strings['methods']['dnsdumpster']['no-connect']
            )
            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            print(result)
            self.context.out(
                message=self.context.strings['methods']['dnsdumpster']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Busca todos los resultados
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(self.context.baseHostname).encode() + br')<',
            result['response-content']
        )

        # ¿Hay resultados?
        if(len(matches) == 0):
            self.context.out(
                self.context.strings['methods']['dnsdumpster']['empty']
            )
            return

        # Procesa todos los subdominios encontrados
        for item in matches:

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=item.decode(),
                messageFormat=self.context.strings['methods']['dnsdumpster']['item-found']
            )
