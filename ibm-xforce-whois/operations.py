"""
Copyright start
Copyright (C) 2008 - 2021 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""
import base64

import requests

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('ibm-xforce-whois')


class IBMXWHOIS(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.api_password = config.get('api_password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint=None, method='GET', data=None, params=None, files=None):
        try:
            url = self.server_url + endpoint
            b64_credential = base64.b64encode((self.api_key + ":" + self.api_password).encode('utf-8')).decode()
            headers = {'Authorization': "Basic " + b64_credential, 'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_whois_info(config, params):
    ip_rep = IBMXWHOIS(config)
    endpoint = 'whois/' + str(params.get('host'))
    return ip_rep.make_request(endpoint=endpoint)


def _check_health(config):
    try:
        params = {'host': '8.8.8.8'}
        res = get_whois_info(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_whois_info': get_whois_info
}
