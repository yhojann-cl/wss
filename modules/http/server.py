import json
import os

from flask import *
from resources.util.helpers import Helper
from modules.filters.ports import FilterPorts
from modules.filters.http import FilterHttpServices
from modules.filters.rawports import FilterRawPorts

from modules.subdomains.axfr import MethodAxfr
from modules.subdomains.dnsqueries import MethodDnsQueries
from modules.subdomains.virustotal import MethodVirusTotal
from modules.subdomains.robtex import MethodRobtex
from modules.subdomains.crtsh import MethodCrtSh
from modules.subdomains.certificatedetails import MethodCertificateDetails
from modules.subdomains.google import MethodGoogle
from modules.subdomains.bing import MethodBing
from modules.subdomains.dnsdumpster import MethodDnsDumpster
from modules.subdomains.dictionary import MethodDictionary

TEMPLATE_DIR = os.path.join(os.getcwd(), 'modules/http/templates')
STATIC_DIR = os.path.join(os.getcwd(), 'modules/http/static')

HTTP = Flask("WSS API REST",
             template_folder=TEMPLATE_DIR,
             static_folder=STATIC_DIR,
             static_url_path='')


class HttpServer(object):

    host = 0
    port = 0
    debug = 'off'
    """
        HTTP server mode for WHK Subdomain Scanner
    """
    def __init__(self, host, port, debug='off'):
        self.host = host
        self.port = port
        self.debug = debug
        if debug == 'on':
            HTTP.config['ENV'] = 'development'
        else:
            HTTP.config['ENV'] = 'production'

    @HTTP.route('/', methods=['GET'])
    def dashboard():
        h = Helper()
        return render_template('dashboard.html', version=h.version())

    @HTTP.route('/filters', methods=['POST'])
    def filters():
        response_bad_request = {'message': 'Bad Request'}
        if request.is_json is True:
            req = request.get_json()
            if 'filter' not in req:
                return response_bad_request, 400
            elif 'host' not in req:
                return response_bad_request, 400
            else:
                try:
                    return HttpServer.run_filter(req)
                except Exception as e:
                    return response_bad_request, 400
        else:
            return response_bad_request, 400

    @HTTP.route('/methods', methods=['POST'])
    def methods():
        response_bad_request = {'message': 'Bad Request'}
        if request.is_json is True:
            req = request.get_json()
            if 'methods' not in req:
                return response_bad_request, 400
            elif 'host' not in req:
                return response_bad_request, 400
            else:
                try:
                    return HttpServer.run_method(req)
                except Exception as e:
                    print(e)
                    return response_bad_request, 400
        else:
            return response_bad_request, 400

    @HTTP.errorhandler(404)
    def not_found(error):
        return {'message': 'error', 'stack': str(error)}, 404

    @HTTP.errorhandler(405)
    def method_not_allowed(error):
        return {'message': 'method isn\'t allowed for this route'}, 405

    @HTTP.errorhandler(400)
    def bad_request(error):
        e = str(error)
        return {'message': e}, 400

    def start(self):
        HTTP.run(host=self.host, port=self.port, debug=self.debug)

    @staticmethod
    def run_filter(req):

        method = int(req.get('filter'))
        data = {'message': 'Unknown filter method'}

        if (method == 1):
            filter_ports = FilterPorts()
            data = {'data': filter_ports.findPorts(req.get('host'))}
        elif (method == 2):
            filter_ws = FilterHttpServices()
            data = {'data': filter_ws.findHttpServices(req.get('host'))}
        elif (method == 3):
            if ((os.geteuid() == 0) or (os.getenv('SUDO_USER') is not None)):
                filter_raw = FilterRawPorts()
                data = {'data': filter_raw.filter(req.get('host'))}
            else:
                data = {'message': 'Not privileges granted'}
        return data

    @staticmethod
    def run_method(req):

        methods = req.get('methods')
        if not isinstance(methods, list):
            return {'message': 'Invalid \'methods\' value'}

        data = {}

        for m in methods:
            if (m == 'axfr'):
                axfr = MethodAxfr()
                data['axfr'] = {'data': axfr.find(req.get('host'))}
            elif (m == 'bing'):
                bing = MethodBing()
                data['bing'] = {'data': bing.find(req.get('host'))}
            elif (m == 'crtdtl'):
                crtdtl = MethodCertificateDetails()
                data['certificatedetails'] = {'data': crtdtl.find(req.get('host'))}
            elif (m == 'crt'):
                crt = MethodCrtSh()
                data['crtsh'] = {'data': crt.find(req.get('host'))}
            elif (m == 'dnsd'):
                dnsd = MethodDnsDumpster()
                data['dnsdumpster'] = {'data': dnsd.find(req.get('host'))}
            elif (m == 'dnsq'):
                dnsq = MethodDnsQueries()
                data['dnsqueries'] = {'data': dnsq.find(req.get('host'))}
            elif (m == 'robt'):
                robt = MethodRobtex()
                data['robtex'] = {'data': robt.find(req.get('host'))}
            elif (m == 'virust'):
                virust = MethodVirusTotal()
                data['virustotal'] = {'data': virust.find(req.get('host'))}
        return data
