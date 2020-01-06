#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.exception
import re
import socket

from resources.util.helpers import Helper


class MethodDnsQueries:
    def __init__(self):
        # Tiempo de espera por defecto para el módulo del socket
        socket.setdefaulttimeout = 0.50

    def find(self, hostname):
        h = Helper()
        # Pila local de subdominios encontrados que evita al duplicidad
        hostnames = []
        # Procesa cada tipo de registro DNS
        for recordType in ['MX', 'TXT', 'SPF', 'NS']:

            # ¿Hubo respuesta?
            answer = None
            try:
                answer = dns.resolver.query(
                    hostname,
                    recordType,
                    tcp=True  # Mejora el resultado, evita la pérdida de paquetes
                )

            except Exception as e:
                # No fue posible realizar la consulta DNS
                continue

            for rdata in answer:

                # Registro en texto plano y en bruto
                plainRecord = rdata.to_text().strip('"')

                # Busca todos los posibles subdominios en la respuesta plana
                matches = re.findall(
                    r'([a-zA-Z0-9\.\-\_\$]+?\.' + re.escape(hostname) + r')',
                    plainRecord)

                # ¿Hay resultados?
                if (len(matches) == 0):
                    continue

                # Procesa cada subdominio encontrado
                for item in matches:

                    if (
                            # Es un subdominio válido?
                        (not item.endswith(h.formatter('.{}', [hostname]))) or
                            # ¿El subdominio existe en la pila local? (evita la
                            # duplicidad de resultados).
                        (item in hostnames)):
                        continue
                    # Agrega el subdominio encontrado a la pila local
                    hostnames.append({
                        'subdomain': item,
                        'recordType': recordType
                    })

        # ¿Hubo resultados finalmente?
        if len(hostnames):
            return hostnames
        else:
            return []
