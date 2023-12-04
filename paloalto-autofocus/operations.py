import json
from pan.afapi.v1_0 import PanAFapi
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('paloalto-autofocus')


class AutoFocus:
    def __init__(self, config):
        self.hostname = config.get('server_url').strip('/')
        if self.hostname.startswith('https://'):
            self.hostname = self.hostname.replace('https://', '')
        self.version = 'v1.0'
        self.error_msg = {
            400: 'Bad/Invalid Request',
            401: 'Invalid credentials were provided',
            403: 'Access Denied',
            404: 'Not Found',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'
        }
        self.afapi_obj = PanAFapi(
                             panrc_tag='autofocus',
                             api_key=config.get('api_key'),
                             verify_cert=config['verify_ssl'],
                             hostname=self.hostname,
                             api_version=self.version
                             )


def construct_payload(field, value):
    body = dict()
    scope = 'global'  # Scope of the search private, public, global
    start = 0         # Sample number from which to start.
    size = 4000       # Number of results to provide default is 50.
    body['scope'] = scope
    body['from'] = start
    body['size'] = size
    body['sort'] = {'create_date': {'order': 'desc'}}
    body['query'] = {'operator': 'all', 'children': [{'field': field, 'operator': 'contains', 'value': value}]}
    return json.dumps(body)


def handle_hunt_action(field, value, afapi_obj):
    try:
        request_payload = construct_payload(field, value)
        res = afapi_obj.samples_search_results(data=request_payload)
        return res
    except Exception as e:
        logger.error('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def hunt_ip(config, params):
    af_obj = AutoFocus(config)
    return handle_hunt_action('alias.ip_address', params.get('ip'), af_obj.afapi_obj)


def hunt_file(config, params):
    af_obj = AutoFocus(config)
    return handle_hunt_action('alias.hash', params.get('hash'), af_obj.afapi_obj)


def hunt_domain(config, params):
    af_obj = AutoFocus(config)
    return handle_hunt_action('alias.domain', params.get('domain'), af_obj.afapi_obj)


def hunt_url(config, params):
    af_obj = AutoFocus(config)
    return handle_hunt_action('alias.url', params.get('url'), af_obj.afapi_obj)


def get_report(config, params):
    af_obj = AutoFocus(config)
    response = af_obj.afapi_obj.tag(tagname=params.get('tag'))
    return response.json()


def _check_health(config):
    af_obj = AutoFocus(config)
    try:
        response = af_obj.afapi_obj.export()
        response = response.json()
        if af_obj.error_msg[response.status_code]:
            raise ConnectorError('{}'.format(af_obj.error_msg[response.status_code]))
        response.raise_for_status()
    except Exception as e:
        logger.error('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'hunt_ip': hunt_ip,
    'hunt_file': hunt_file,
    'hunt_domain': hunt_domain,
    'hunt_url': hunt_url,
    'get_report': get_report
}
