#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper


class MethodVirusTotal:
    hostnames = []

    def __init__(self):
        pass

    def find(self, hostname, url=None):
        h = Helper()
        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None
        if url is None:
            req = h.formatter(
                'https://www.virustotal.com/ui/domains/{}/subdomains?limit=40',
                [hostname])
        else:
            req = url
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

        # ¿Hay contenido de la respuesta HTTP?
        if (len(result['data']) == 0):
            return []

        # Procesa todos los subdominios encontrados en la página actual
        for item in result['data']:

            # Evita los resultados duplicados utilizando la pila local
            if (str(item['id']) in self.hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            self.hostnames.append(str(item['id']))

        # ¿Necesita continuar paginando resultados?
        if (('links' in result) and ('next' in result['links'])
                and (result['links'])):
            self.find(hostname=hostnames, url=str(result['links']['next']))
            
        return self.hostnames
