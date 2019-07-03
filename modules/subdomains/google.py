#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from modules.helpers.crawler import WCrawler


class MethodGoogle:

    def __init__(self, context):

        # El contexto principal
        self.context = context
        
        # Variable que permite entregar subdominios únicos (no duplicados)
        self.hostnames = []

        # Llave API-KEY de Google
        # Viene con una personal de regalo, si está saturada y google deniega
        # las solicitudes deberás utilizar tu propia API-KEY.
        self.googleApiKey = 'AIzaSyD_NlD2Lz1OgewxdZasjCquLo6AWYdeJz0'

        # Identificador del buscador (*.cl, *.com, *.org, *.edu, *.net, *.py,
        # *.gob, *.gov). Puedes utilizar tu propio Id de buscador de google con
        # tus propias extensiones: https://cse.google.com/
        self.googleCx = '010763716184496466486:fscqb-8v6rs'


    def find(self):

        # Mensaje de la cabecera del método
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['google']['title']
            }
        )

        # ¿La llave de la API de Google existe?
        if(not self.googleApiKey.strip()):
            self.context.out(
                self.context.strings['methods']['google']['no-api-key']
            )
            return

        # Busca en la primera página (de manera recursiva)
        self.paginate()


    def paginate(self, pageNumber=1):

        # Contexto de la búsqueda de la página actual
        searchContext = {
            'max-pages'   : 15,
            'max-result'  : 10,
            'start-index' : 1,
            'query'       : 'site:' + self.context.baseHostname
        }
        
        # ¿Hay resultados del método actual?
        if(self.hostnames):

            # Excluye los subdominios ya conocidos
            searchContext['query'] += ' -site:' + ' -site:'.join(self.hostnames)

        # Número del resultado de inicio actual
        searchContext['start-index'] = (
            ((pageNumber - 1) * searchContext['max-result']) + 1
        )

        # Mensaje inicial de la paginación
        self.context.out(
            self.context.strings['methods']['google']['pagination']
        )

        # Uso del crawler
        crawler = WCrawler()

        # El resultado es de tipo json
        result = None

        try:
            # Navega
            result = crawler.httpRequest(
                'https://www.googleapis.com/customsearch/v1?' +
                'cx='     + crawler.urlencode(self.googleCx) +
                '&key='   + crawler.urlencode(self.googleApiKey) +
                '&q='     + crawler.urlencode(searchContext['query']) +
                '&start=' + str(searchContext['start-index']) + 
                '&filter=1&safe=off&num=' + str(searchContext['max-result'])
            )

            # Libera la memoria (no es necesario un contexto de navegación)
            crawler.clearContext()

        except Exception as e:

            # Imposible navegar
            self.context.out(
                self.context.strings['methods']['google']['no-connect']
            )

            return

        # Los estados 403 y 400 indican que no hay más resultados o que la API
        # está saturada con solicitudes.
        if(result['status-code'] in [403, 400]):
            self.context.out(
                self.context.strings['methods']['google']['no-more-results']
            )
            return

        # ¿La respuesta HTTP es OK?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['google']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        try:
            # Convierte el resultado en un objeto de tipo json
            result = json.loads(result['response-content'])

        except Exception as e:

            # Contenido corrupto, no es de tipo json procesable
            self.context.out(
                self.context.strings['methods']['google']['corrupt-response']
            )

            return

        # ¿Hay resultados procesables?
        if(
            (not 'items' in result) or
            (len(result['items']) == 0)
        ):

            # No hay más resultados
            self.context.out(
                self.context.strings['methods']['google']['no-more-results']
            )

            return

        # Procesa cada resultado
        for item in result['items']:
            
            # ¿El resultado es un subdominio inválido?
            if(not item['displayLink'].endswith('.' + self.context.baseHostname)):
                continue
            
            # Evita los resultados duplicados utilizando la pila local
            if(item['displayLink'] in self.hostnames):
                continue

            # Agrega el subdominio encontrado a la pila local
            self.hostnames.append(item['displayLink'])

            # Agrega el subdominio encontrado a la pila global de resultados
            self.context.addHostName(
                hostname=item['displayLink'],
                messageFormat=self.context.strings['methods']['google']['item-found']
            )

            # Retorna a la primera página nuevamente debido a que la búsqueda
            # debe contener la exclusión del subdominio encontrado, por ejemplo:
            # site: example.com -site:foo.example.com
            pageNumber = 0

        # Límite de busqueda de páginas
        if(pageNumber >= searchContext['max-pages']):
            self.context.out(
                self.context.strings['methods']['google']['no-more-results']
            )
            return

        # Continua con la siguiente página
        self.paginate(pageNumber=pageNumber + 1)