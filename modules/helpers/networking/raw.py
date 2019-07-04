#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import textwrap
import netifaces
import random


class Interface(object):

    def __init__(self):

        pass
        

    def getSourceAddress(self):

        return (
            [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] 
            if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), 
            s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
        )


    def getDefaultInterface(self):
        return netifaces.gateways()['default'][netifaces.AF_INET][1]


class Ethernet(object):

    def __init__(self, rawData):

        (
            dest,
            src,
            prototype

        ) = struct.unpack(
            '! 6s 6s H',
            rawData[:14]
        )

        self.data    = rawData[14:]
        self.destMac = self.getMacAddr(dest)
        self.srcMac  = self.getMacAddr(src)

        # 8: IPv4
        self.proto   = socket.htons(prototype)


    def getMacAddr(self, mac_raw):
        return ':'.join(map('{:02x}'.format, mac_raw)).upper()

    
    def isIpV4(self):
        return (self.proto == 8)


class ICMP(object):

    def __init__(self, rawData):

        (
            self.type,
            self.code,
            self.checksum

        ) = struct.unpack(
            '! B B H',
            rawData[:4]
        )
        
        self.data = rawData[4:]


class IPv4(object):

    def __init__(self, rawData):

        # self.proto
        # 1 : ICMP
        # 6 : TCP
        # 17: UDP

        (
            self.ttl,
            self.proto,
            src,
            target

        ) = struct.unpack(
            '! 8x B B 2x 4s 4s',
            rawData[:20]
        )
        
        versionHeaderLength = rawData[0]
        self.version        = versionHeaderLength >> 4
        self.headerLength   = (versionHeaderLength & 15) * 4
        self.src            = '.'.join(map(str, src))
        self.target         = '.'.join(map(str, target))
        self.data           = rawData[self.headerLength:]


    def isICMP(self):
        return (self.proto == 1)


    def isTCP(self):
        return (self.proto == 6)


    def isUDP(self):
        return (self.proto == 17)


class TCP(object):

    def __init__(self, rawData):

        (
            self.srcPort,
            self.destPort,
            self.sequence,
            self.acknowledgment,
            offsetReservedFlags

        ) = struct.unpack(
            '! H H L L H',
            rawData[:14]
        )
        
        offset       = (offsetReservedFlags >> 12) * 4
        self.flagUrg = bool((offsetReservedFlags & 32) >> 5)
        self.flagAck = bool((offsetReservedFlags & 16) >> 4)
        self.flagPsh = bool((offsetReservedFlags & 8) >> 3)
        self.flagRst = bool((offsetReservedFlags & 4) >> 2)
        self.flagSyn = bool((offsetReservedFlags & 2) >> 1)
        self.flagFin = bool(offsetReservedFlags & 1)
        self.data    = rawData[offset:]


class TCPHelper(object):

    def __init__(self):

        pass


    def sendSyn(self, sourceIp, toAddress, dstPort):

        # Cabecera IP
        ipHeader = {
            'ihl'            : 5,
            'version'        : 4,
            'tos'            : 0,
            'tot-len'        : (20 + 20),
            'packet-id'      : int((id(1) * random.random()) % 65535),
            'frag-off'       : 0,
            'ttl'            : 255,
            'protocol'       : socket.IPPROTO_TCP,
            'check'          : 10,
            'source-address' : socket.inet_aton(sourceIp),
            'dest-address'   : socket.inet_aton(toAddress)
        }
         
        ihlVersion = (ipHeader['version'] << 4) + ipHeader['ihl']
         
        ipHeaderPacked = struct.pack(
            '!BBHHHBBH4s4s',
            ihlVersion,
            ipHeader['tos'],
            ipHeader['tot-len'],
            ipHeader['packet-id'],
            ipHeader['frag-off'],
            ipHeader['ttl'],
            ipHeader['protocol'],
            ipHeader['check'],
            ipHeader['source-address'],
            ipHeader['dest-address']
        )
         
        # Cabecera TCP
        tcpHeader = {
            'source'  : 9999, # random.randint(1, 65535), # Fuente (puerto)
            'seq'     : 0,
            'ack-seq' : 0,
            'doff'    : 5, # 4 bit, tamaño de la cabecera TCP, 5 * 4 = 20 bytes
            'flags'   : {
                'fin'     : 0,
                'syn'     : 1,
                'rst'     : 0,
                'psh'     : 0,
                'ack'     : 0,
                'urg'     : 0,
            },
            'window'  : socket.htons(5840), # Tamaño máximo permitido
            'check'   : 0,
            'urg-ptr' : 0
        }

        offsetRes = (tcpHeader['doff'] << 4) + 0

        tcpFlags = (
            (tcpHeader['flags']['fin']) +
            (tcpHeader['flags']['syn'] << 1) +
            (tcpHeader['flags']['rst'] << 2) +
            (tcpHeader['flags']['psh'] << 3) +
            (tcpHeader['flags']['ack'] << 4) +
            (tcpHeader['flags']['urg'] << 5)
        )
         
        tcpHeaderPacked = struct.pack(
            '!HHLLBBHHH',
            tcpHeader['source'],
            dstPort,
            tcpHeader['seq'],
            tcpHeader['ack-seq'],
            offsetRes,
            tcpFlags,
            tcpHeader['window'],
            tcpHeader['check'],
            tcpHeader['urg-ptr']
        )
         
        placeholder = 0
        psh = struct.pack(
            '!4s4sBBH',
            ipHeader['source-address'],
            ipHeader['dest-address'],
            placeholder,
            ipHeader['protocol'],
            len(tcpHeaderPacked)
        )
        psh = psh + tcpHeaderPacked
         
        tcpChecksum = self.checksum(psh)
         
        # Crea nuevamente la cabecera del paquete con el checksum
        tcpHeaderPacked = struct.pack(
            '!HHLLBBHHH',
            tcpHeader['source'],
            dstPort,
            tcpHeader['seq'],
            tcpHeader['ack-seq'],
            offsetRes,
            tcpFlags,
            tcpHeader['window'],
            tcpChecksum,
            tcpHeader['urg-ptr']
        )
         
        # El paquete no tiene ningun contenido adicional
        packet = (ipHeaderPacked + tcpHeaderPacked)
         
        # Socket que enviará el paquete
        socketHandler = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_TCP
        )

        # Incluye las cabeceras IP
        socketHandler.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Envía el paquete
        socketHandler.sendto(packet, (toAddress , 0))
    

    def checksum(self, data):

        checksum = 0

        for indexByte in range(0, len(data), 2):
            checksumPart = ((data[indexByte]) << 8) + (data[indexByte + 1])
            checksum = checksum + checksumPart

        checksum = (checksum >> 16) + (checksum & 0xffff);
        
        # Máscara a 4 bytes
        checksum = ~checksum & 0xffff

        return checksum


class UDP(object):

    def __init__(self, rawData):
        
        (
            self.src_port,
            self.dest_port,
            self.size
            
        ) = struct.unpack(
            '! H H 2x H',
            rawData[:8]
        )

        self.data = rawData[8:]
