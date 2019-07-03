#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.exception
import re
import socket


class MethodDnsQueries:

    def __init__(self, context):

        # El contexto principal
        self.context = context

        # Tiempo de espera por defecto para el módulo del socket
        socket.setdefaulttimeout = 0.50


    def find(self):

        # Mensaje de la cabecera del método
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['dns-queries']['title']
            }
        )

        # Variable que indica si hubieron subdominios encontrados o no
        found = False

        # Procesa cada tipo de registro DNS
        for recordType in ['MX', 'TXT', 'SPF', 'NS']:

            # Mensaje principal de la búsqueda del registro actual
            self.context.out(
                message=self.context.strings['methods']['dns-queries']['title-query-type'],
                parseDict={
                    'type': recordType
                }
            )

            # ¿Hubo respuesta?
            answer = None
            try:
                answer = dns.resolver.query(
                    self.context.baseHostname,
                    recordType,
                    tcp=True # Mejora el resultado, evita la pérdida de paquetes
                )

            except Exception as e:
                # No fue posible realizar la consulta DNS
                continue

            for rdata in answer:

                # Pila local de subdominios encontrados que evita al duplicidad
                hostnames = []

                # Registro en texto plano y en bruto
                plainRecord = rdata.to_text().strip('"')

                # Busca todos los posibles subdominios en la respuesta plana
                matches = re.findall(
                    r'([a-zA-Z0-9\.\-\_\$]+?\.' + re.escape(self.context.baseHostname) + r')',
                    plainRecord
                )

                # ¿Hay resultados?
                if(len(matches) == 0):
                    continue

                # Procesa cada subdominio encontrado
                for item in matches:

                    if(
                        # Es un subdominio válido?
                        (not item.endswith('.' + self.context.baseHostname)) or

                        # ¿El subdominio existe en la pila local? (evita la 
                        # duplicidad de resultados).
                        (item in hostnames)
                    ):
                        continue
                        
                    # Está bien, hay subdominios
                    found = True

                    # Agrega el subdominio encontrado a la pila local
                    hostnames.append(item)

                    # Agrega el subdominio encontrado a la pila global de resultados
                    self.context.addHostName(
                        hostname=item,
                        messageFormat=self.context.strings['methods']['dns-queries']['item-found']
                    )
        
        # ¿Hubo resultados finalmente?
        if(not found):

            # No, no hubo resultados
            self.context.out(
                self.context.strings['methods']['dns-queries']['no-items-found']
            )
