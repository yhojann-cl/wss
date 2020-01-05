#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper


class MethodCertificateDetails:
    def __init__(self):

        # Variable que permite entregar subdominios únicos (no duplicados)
        self.hostnames = []

    def find(self, hostname):

        h = Helper()

        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None
        req = h.formatter('https://certificatedetails.com/api/list/{}',
                          [hostname])
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

        # Procesa cada nombre de dominio encontrado
        items = []
        for item in result:
            subdomain = h.formatter('.{}', [hostname])
            # ¿Es un subdominio válido?
            if (not item['CommonName'].endswith(subdomain)):
                continue

            # Evita los resultados duplicados utilizando la pila local
            if (item['CommonName'] in items):
                continue

            # Agrega el subdominio encontrado a la pila local
            items.append(item['CommonName'])

        self.hostnames.append({'subdomains': items})

        # Identificador actual del enlace
        linkId = 0

        # Procesa cada enlace
        # Precaución: Un mismo nombre de dominio repetido puede contener uno o
        #             más certificados diferentes.
        linkres = []
        for item in result:

            linkId += 1
            req = h.formatter('https://certificatedetails.com{}',
                              [item['Link']])
            linkres += self.findInLink(url=req,
                                       linkId=linkId,
                                       totalLinks=len(result),
                                       hostname=hostname)
        self.hostnames.append({'links': linkres})
        return self.hostnames

    def findInLink(self, url, linkId, totalLinks, hostname):

        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo HTML
        result = None

        try:
            result = crawler.httpRequest(url=url)

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:
            return []

        # ¿La respuesta HTTP es OK?
        if (result['status-code'] != 200):
            # Nothing
            return []

        # Busca todos los posibles subdominios
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(hostname).encode() + br')<',
            result['response-content'])

        # ¿Hay resultados?
        if (len(matches) == 0):
            return []

        # Procesa cada nombre de dominio
        links = []
        for item in matches:
            it = item.decode()
            if not it in links:
                # Agrega el subdominio encontrado a la pila local
                links.append(it)

        return list(set(links))
