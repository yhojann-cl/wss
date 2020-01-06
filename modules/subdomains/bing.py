#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper

class MethodBing:
    def __init__(self):

        # Variable que permite entregar subdominios únicos (no duplicados)
        self.hostnames = []

    def find(self, hostname):

        h = Helper()
        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None

        mp = 15
        q  = h.formatter('domain:{}', [hostname])

        for p in range(1, 16):
            req = h.formatter('https://www.bing.com/search?q={}&first={}', [q, p])
            try:
                result = crawler.httpRequest(req)
                # Libera la memoria (no es necesario un contexto de navegación)
                crawler.clearContext()
            except Exception as e:
                return []

            # ¿La respuesta HTTP es OK?
            if (result['status-code'] != 200):
                return []
            # Busca cada nombre de dominio
            # Ejemplo de resultados: <cite>https://foo<strong>ejemplo.com</strong>
            matches = re.findall(
                br'>([\w\.\-\_\$]+?\.' + re.escape(hostname).encode() + br')',
                result['response-content'].replace(b'<strong>' + hostname.encode(),
                                                   b'.' + hostname.encode()))

            if (len(matches) == 0):
                return []

            # Procesa cada nombre de dominio encontrado
            for item in matches:
                # ¿El resultado es un subdominio inválido?
                if (not item.decode().endswith('.' + hostname)):
                    continue

                # Evita los resultados duplicados utilizando la pila local
                if (item.decode() in self.hostnames):
                    continue

                # Agrega el subdominio encontrado a la pila local
                self.hostnames.append(item.decode())

        return self.hostnames