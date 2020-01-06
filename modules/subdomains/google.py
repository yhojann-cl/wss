#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper


class MethodGoogle:
    def __init__(self):
        # Llave API-KEY de Google
        # Viene con una personal de regalo, si está saturada y google deniega
        # las solicitudes deberás utilizar tu propia API-KEY.
        self.googleApiKey = 'AIzaSyD_NlD2Lz1OgewxdZasjCquLo6AWYdeJz0'

        # Identificador del buscador (*.cl, *.com, *.org, *.edu, *.net, *.py,
        # *.gob, *.gov). Puedes utilizar tu propio Id de buscador de google con
        # tus propias extensiones: https://cse.google.com/
        self.googleCx = '010763716184496466486:fscqb-8v6rs'

    def find(self, hostname):
        h = Helper()
        # ¿La llave de la API de Google existe?
        if (not self.googleApiKey.strip()):
            return []

        q = h.formatter('site:{}', [hostname])
        hostnames = []
        
        for i in range(1, 16):
            # ¿Hay resultados del método actual?
            if (hostnames):
                # Excluye los subdominios ya conocidos
                q += h.formatter('-site:{}', [' -site:'.join(hostnames)])
            # Uso del crawler
            crawler = WCrawler()

            # El resultado es de tipo json
            result = None
            req = h.formatter(
                'https://www.googleapis.com/customsearch/v1?cx={}&key={}&q={}&start={}&filter=1&safe=off&num={}',
                [self.googleCx, self.googleApiKey, q, i, 10])
            try:
                # Navega
                result = crawler.httpRequest(req)

                # Libera la memoria (no es necesario un contexto de navegación)
                crawler.clearContext()

            except Exception as e:
                break

            # Los estados 403 y 400 indican que no hay más resultados o que la API
            # está saturada con solicitudes.
            if (result['status-code'] in [403, 400]):
                break

            # ¿La respuesta HTTP es OK?
            if (result['status-code'] != 200):
                break

            try:
                # Convierte el resultado en un objeto de tipo json
                result = json.loads(result['response-content'])
            except Exception as e:
                break

            # ¿Hay resultados procesables?
            if ((not 'items' in result) or (len(result['items']) == 0)):
                break

            # Procesa cada resultado
            for item in result['items']:

                f = h.formatter('.{}', [hostname])
                # ¿El resultado es un subdominio inválido?
                if (not item['displayLink'].endswith(f)):
                    continue

                # Evita los resultados duplicados utilizando la pila local
                if (item['displayLink'] in hostnames):
                    continue

                # Agrega el subdominio encontrado a la pila local
                hostnames.append(item['displayLink'])

        return hostnames