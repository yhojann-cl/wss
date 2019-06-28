#!/usr/bin/python3
# _*_ coding:utf-8 _*_

import random
import re
import threading
import socket
import ssl
from urllib import parse
from urllib.parse import urlencode
import urllib.parse


class WCrawler(object):
    

    def __init__(self):

        self.cookies = {}
        self.lastUrl = None


    def clearContext(self):

        # Make a new instance
        self.cookies = {}
        self.lastUrl = None


    def httpRequest(
        self,
        url,
        customHeaders=None,
        postData=None
    ):
        # to bytes array
        if(not isinstance(url, bytes)):
            url = str(url).encode('utf-8', 'ignore')

        if(postData):
            
            if(isinstance(postData, dict)):
                postData = urlencode(postData).encode('utf-8', 'ignore')

            if(isinstance(postData, str)):
                postData = postData.encode('utf-8', 'ignore')

#        if(customHeaders):
#            # Join custom headers
#            headers.update(customHeaders)

        #Formatea la dirección URL
        urlParsed = parse.urlparse(url)
        urlData = {
            'original' : url,
            'path'     : urlParsed.path,
            'host'     : urlParsed.netloc,
            'port'     : urlParsed.port,
            'scheme'   : urlParsed.scheme,
            'query'    : urlParsed.query,
            'uri'      : urlParsed.path + ((b'?' + urlParsed.query) if urlParsed.query else b'')
        }

        if urlData['path'] == b'':
            urlData['path'] = b'/'

        if(not urlData['port']):
            urlData['port'] = 443 if (urlData['scheme'] == b'https') else 80

        # Strip the custom port from the hostname
        if(b':' in urlData['host']):
            urlData['host'] = urlData['host'].split(b':')[0]
            
        packet = None

        if(postData):
            packet = b'\r\n'.join([
                b'POST ' + urlData['uri'] + b' HTTP/1.1',
                b'Host: ' + urlData['host'],
                b'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/54.0',
                b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                b'Accept-Language: en-US',
                b'Referer: ' + (self.lastUrl if self.lastUrl else url),
                b'Cookie: ' + self.getCookiesHttpFormat(),
                b'Content-Type: application/x-www-form-urlencoded',
                b'Content-Length: ' + str(len(postData)).encode('utf-8'),
                b'Connection: close',
                b'',
                postData
            ])

        else:
            packet = b'\r\n'.join([
                b'GET ' + urlData['uri'] + b' HTTP/1.1',
                b'Host: ' + urlData['host'],
                b'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/54.0',
                b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                b'Accept-Language: en-US',
                b'Referer: ' + (self.lastUrl if self.lastUrl else url),
                b'Cookie: ' + self.getCookiesHttpFormat(),
                b'Connection: close',
                b'\r\n'
            ])

        self.lastUrl = url

        socketHandler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketHandler.settimeout(10)
        
        # Usa SSL?
        if(urlData['scheme'] == b'https'):
            socketWraped = ssl.create_default_context().wrap_socket(
                socketHandler,
                server_hostname=urlData['host'].decode()
            )
        else:
            socketWraped = socketHandler

        # Connect to server
        socketWraped.connect((urlData['host'].decode(), int(urlData['port'])))

        socketWraped.send(packet)

        bytesRresponse = b''
        while True:
            bytesPart = socketWraped.recv(1024)
            bytesRresponse = bytesRresponse + bytesPart
            if bytesPart == b'':
                break
        socketWraped.shutdown(1)
        socketWraped.close()

        # Save the cookies
        self.parseCookiesByHttpResponse(bytesRresponse)

        statusCode = 0
        matches = re.search(br'HTTP\/\d\.\d (\d+) ', bytesRresponse, re.IGNORECASE | re.MULTILINE)
        if(matches):
            statusCode = int(matches.group(1))

        body = bytesRresponse.split(b'\r\n\r\n')
        headers = body.pop(0).strip()
        body = b'\r\n'.join(body)

        # Decodifica las cabeceras
        if(b'\r\n' in headers):
            tmp = {}
            for item in headers.split(b'\r\n'):
                value = item.split(b':')
                key = value.pop(0).strip()
                value = b':'.join(value).strip()
                tmp[key] = value
            headers = tmp

        # TODO: Support?
        # Transfer-Encoding: chunked  [OK]
        # Transfer-Encoding: compress
        # Transfer-Encoding: deflate
        # Transfer-Encoding: gzip
        # Transfer-Encoding: identity

        if(b'Transfer-Encoding' in headers):
        
            # Chunked response body?
            # https://tools.ietf.org/rfc/rfc7230.txt
            if(headers[b'Transfer-Encoding'] == b'chunked'):

                # Length in hex, convert to int base 16
                bytesLength = b''
                byteLength  = 0
                bytesBody   = b''

                while(True):

                    # Find next bytes length
                    if(body[:1] != b'\n'):
                        if(body[:1] != b'\r'):
                            bytesLength += body[:1]
                        body = body[1:]

                    else:

                        # End of bytes?
                        if(bytesLength == b'0'):
                            break

                        # Strip \n
                        body = body[1:]
                        
                        # Add to real body
                        bytesBody += body[:int(bytesLength, 16)]

                        # Pop bytes (less memory usage)
                        body = body[int(bytesLength, 16) + 2:] # 2:\r\n

                        # Reset length
                        bytesLength = b''

                # Transfer value
                body = bytesBody

                # Free memory
                bytesBody = None

        # Return the result
        return {
            'status-code'      : statusCode,
            'response-content' : body,
            'response-headers' : headers,
            'request-content'  : packet
        }


    def getCookiesHttpFormat(self):
        cookies = []
        for key, value in self.cookies.items():
            cookies.append(key + b'=' + value)
        return b'; '.join(cookies)


    def parseCookiesByHttpResponse(self, buffer_response):
        cookies = []
        matches = re.findall(br'set\-cookie:\s*(.*?);', buffer_response, re.IGNORECASE | re.MULTILINE)

        if len(matches) > 0:
            for cookie in matches:

                cookie = re.search(rb'(.*?)=(.*)', cookie, re.IGNORECASE | re.MULTILINE)
                
                var = cookie.group(1).strip()
                val = cookie.group(2).strip()

                if val:
                    self.cookies[var] = val

                else:
                    # Si la cookie existe la eliminará
                    if var in self.cookies.keys():
                        self.cookies.pop(var, None)


    def urlencode(self, payload):

        return urllib.parse.quote_plus(payload)