#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper

class MethodDnsDumpster(object):

    def __init__(self):
        pass


    def find(self, hostname):
        h = Helper()
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
            return []

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            return []

        # Busca el token XSRF
        matches = re.search(
            br'name=["\']csrfmiddlewaretoken["\']\s+value=["\'](.+?)["\']',
            result['response-content'],
            re.I | re.M
        )
        
        if(not matches):
            return []

        # Guarda el roken XSRF en la variable local para reutilizar la variable
        # 'matches'.
        tokenXsrf = matches.group(1)

        # El resultado es de tipo HTML
        result = None

        try:
            result = crawler.httpRequest(
                url='https://dnsdumpster.com/',
                postData={
                    'csrfmiddlewaretoken' : tokenXsrf,
                    'targetip'            : hostname
                }
            )

        except Exception as e:
            return []

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            return []

        # Busca todos los resultados
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(hostname).encode() + br')<',
            result['response-content']
        )

        # ¿Hay resultados?
        if(len(matches) == 0):
            return []

        hostnames = []
        # Procesa todos los subdominios encontrados
        for item in matches:
            hostnames.append(item.decode())

        return hostnames
