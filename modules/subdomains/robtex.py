#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper


class MethodRobtex:
    def __init__(self):
        pass

    def find(self, hostname):
        h = Helper()
        # Uso del crawler
        crawler = WCrawler()
        crawler.defaultTimeout = 30

        # Resultado de tipo HTML
        result = None
        req = h.formatter('https://www.robtex.com/dns-lookup/{}', [hostname])
        try:
            result = crawler.httpRequest(req)

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            return []

        # ¿La respuesta HTTP es OK?
        if (result['status-code'] != 200):
            return []

        # Elimina las etiquetas de negritas del resultado: foo.<b>domain.com</b>
        result['response-content'] = result['response-content'].replace(
            b'<b>', b'').replace(b'</b>', b'')

        # Busca todos los posibles subdominios
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' +
            re.escape(hostname).encode() + br')<',
            result['response-content'])

        # ¿Hay resultados?
        if (len(matches) == 0):
            return []

        result = []
        # Procesa todos los resultados
        for item in matches:
            result.append(item.decode())

        return result
