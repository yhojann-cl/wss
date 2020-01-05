#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper


class MethodCrtSh:
    def __init__(self):
        pass

    def find(self, hostname):
        h = Helper()
        # Uso del crawler
        crawler = WCrawler()
        crawler.defaultTimeout = 60

        # El resultado es de tipo json
        result = None

        req = h.formatter('https://crt.sh/?q=%.{}&output=json', [hostname])

        try:
            result = crawler.httpRequest(req)

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            return []

        # ¿La respuesta HTTP es OK?
        if (result['status-code'] != 200):
            return []

        try:
            # Convierte el resultado en un objeto de tipo json
            result = json.loads(result['response-content'])

        except Exception as e:
            return []

        if ((not isinstance(result, list)) or (len(result) == 0)):
            return []

        hostnames = []
        # Procesa cada nombre de dominio encontrado
        for item in result:

            # Evita los resultados duplicados utilizando la pila local
            if (item['name_value'] in hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            hostnames.append(item['name_value'])

        return hostnames
