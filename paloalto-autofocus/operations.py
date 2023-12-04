"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

import requests, json
from ipaddress import ip_address, IPv4Address
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('paloalto-autofocus')


class AutoFocus(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/v1.0/'.format(url)
        else:
            self.url = url + '/api/v1.0/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None, flag=None, indicator=None):
        try:
            url = self.url + url
            headers = {
                'Content-Type': 'application/json'
            }
            if flag and not indicator:
                headers.update({'Content-Type': 'application/text', 'apiKey': self.api_key})
            elif flag and indicator:
                headers.update({'apiKey': self.api_key})
            else:
                data.update({'apiKey': self.api_key})
            response = requests.request(method, url, data=json.dumps(data), params=params, headers=headers,
                                        verify=self.verify_ssl)
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def samples_search(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'samples/search/'
        sort_field = params.get('sort_field')
        if sort_field:
            sort_field = {
                "{0}".format(SORT_FIELD.get(sort_field)): {
                    "order": SORT_ORDER.get(params.get('sort_order'))
                }
            }
        data = {
            "query": {
                "operator": params.get('operator').lower() if params.get('operator') else '',
                "children": params.get('query') if params.get('query') else ''
            },
            "size": params.get('size'),
            "from": params.get('from'),
            "type": params.get('type').lower() if params.get('type') else '',
            "sort": sort_field,
            "scope": params.get('scope').lower()
        }
        payload = {k: v for k, v in data.items() if v is not None and v != ''}
        response = af.make_rest_call(endpoint, 'POST', data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_sample_details(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'samples/results/{0}'.format(params.get('search_id'))
        response = af.make_rest_call(endpoint, 'POST', data={})
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def create_multiple_values(values):
    result = []
    for value in values:
        result.append(value.lower())
    return result


def top_tags_search(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'top-tags/search/'
        tag_scopes = params.get('tagScopes')
        if tag_scopes:
            tag_scopes = create_multiple_values(tag_scopes)
        data = {
            "query": {
                "operator": params.get('operator').lower() if params.get('operator') else '',
                "children": params.get('query') if params.get('query') else ''
            },
            "size": params.get('size'),
            "tagScopes": tag_scopes if tag_scopes else '',
            "scope": params.get('scope').lower()
        }
        payload = {k: v for k, v in data.items() if v is not None and v != ''}
        response = af.make_rest_call(endpoint, 'POST', data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_session_details(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'session/{0}'.format(params.get('session_id'))
        response = af.make_rest_call(endpoint, 'POST', data={})
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_tags_list(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'tags/'
        data = {
            "query": params.get('query'),
            "scope": params.get('scope').lower(),
            "pageSize": params.get('pageSize'),
            "pageNum": params.get('pageNum'),
            "sortBy": SORT_BY.get(params.get("sortBy")) if params.get("sortBy") else '',
            "order": SORT_ORDER.get(params.get('order')) if params.get('order') else ''
        }
        payload = {k: v for k, v in data.items() if v is not None and v != ''}
        response = af.make_rest_call(endpoint, 'POST', data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_tag_details(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'tag/{0}'.format(params.get('public_tag_name'))
        response = af.make_rest_call(endpoint, 'POST', data={})
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_ip_reputation(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'tic'
        indicator_value = params.get('indicatorValue')
        indicator_type = "ipv4_address" if type(ip_address(indicator_value)) is IPv4Address else "ipv6_address"
        query_parameter = {
            'indicatorType': indicator_type,
            'indicatorValue': indicator_value,
            'includeTags': params.get('includeTags')
        }
        response = af.make_rest_call(endpoint, 'GET', params=query_parameter, flag=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_domain_reputation(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'tic'
        query_parameter = {
            'indicatorType': 'domain',
            'indicatorValue': params.get('indicatorValue'),
            'includeTags': params.get('includeTags')
        }
        response = af.make_rest_call(endpoint, 'GET', params=query_parameter, flag=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_url_reputation(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'tic'
        query_parameter = {
            'indicatorType': 'url',
            'indicatorValue': params.get('indicatorValue'),
            'includeTags': params.get('includeTags')
        }
        response = af.make_rest_call(endpoint, 'GET', params=query_parameter, flag=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_filehash_reputation(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'tic'
        query_parameter = {
            'indicatorType': 'filehash',
            'indicatorValue': params.get('indicatorValue'),
            'includeTags': params.get('includeTags')
        }
        response = af.make_rest_call(endpoint, 'GET', params=query_parameter, flag=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_threat_indicator_feed(config, params):
    try:
        af = AutoFocus(config)
        endpoint = 'output/threatFeedResult'
        response = af.make_rest_call(endpoint, 'GET', flag=True, indicator=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config):
    try:
        response = get_tags_list(config, params={'pageSize': 1})
        if response:
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'samples_search': samples_search,
    'get_sample_details': get_sample_details,
    'top_tags_search': top_tags_search,
    'get_session_details': get_session_details,
    'get_tags_list': get_tags_list,
    'get_tag_details': get_tag_details,
    'get_ip_reputation': get_ip_reputation,
    'get_domain_reputation': get_domain_reputation,
    'get_url_reputation': get_url_reputation,
    'get_filehash_reputation': get_filehash_reputation,
    'get_threat_indicator_feed': get_threat_indicator_feed
}
