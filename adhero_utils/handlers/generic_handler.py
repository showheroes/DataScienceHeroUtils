import tornado.web
import tornado.auth
import requests
import logging
import json
import traceback
import base64
from binascii import Error as BinasciiError
import time


class GenericHandler(tornado.web.RequestHandler, tornado.auth.OAuth2Mixin):
    """ Generic request handler, defining standard pipeline of validating and processing a request. """

    def initialize(self):
        self.log = logging.getLogger(__name__)
        self._OAUTH_AUTHORIZE_URL = self._get_oauth_authorize_url()
        self._OAUTH_ACCESS_TOKEN_URL = self._get_oauth_access_token_url()

    def _get_oauth_authorize_url(self):
        return self.settings['oauth_server'] + '/oauth/authorize'

    def _get_oauth_access_token_url(self):
        return self.settings['oauth_server'] + '/oauth/token'

    def _get_oauth_user_endpoint_url(self):
        return self.settings['oauth_server'] + '/api/v1/oauth/user'

    # request handling

    def prepare(self):
        """ Set usage dict and authenticate """
        self.start_time = time.time()
        self.usage = self.get_usage()
        # set standard response content type
        self.set_header('Content-Type', self._get_response_content_type())
        # check for existing authentication token
        self.auth_token, self.auth_method = self._get_authentication_token()
        self._authenticate()

    def on_finish(self):
        self.end_time = time.time()
        self.elapsed_time_ms = (self.end_time - self.start_time) * 1000.
        self._collect_statistics()
        # if self.user_token:
        #     self.set_secure_cookie('user_token', self.user_token, expires_days=3)

    def _collect_statistics(self):
        pass

    def get(self, *args, **kwargs):
        """ Standard response for GET requests 405 with is the usage string. """
        self._exit_no_route('GET')

    def post(self, *args, **kwargs):
        """ POST requests check request parameters and execute _process_request """
        self._exit_no_route('POST')

    def put(self, *args, **kwargs):
        """ PUT request standard response."""
        self._exit_no_route('PUT')

    def delete(self, *args, **kwargs):
        """ DELETE standard response """
        self._exit_no_route('DELETE')

    def get_usage(self):
        return {}

    def _check_request_headers(self):
        """ Checks the request headers for the expected content type """
        if not 'Content-Type' in self.request.headers:
            self._exit_error('No Content-Type set, be sure to set the headers appropriately', status=400)
        if not self._accept_content_type(self.request.headers['Content-Type']):
            self._exit_error(
                f"Unexpected content type: {self.request.headers['Content-Type']}, be sure to set request headers appropriately.",
                status=400)

    def _get_accept_content_type(self):
        """ Standard acceptable content type. """
        return 'application/json'

    def _accept_content_type(self, content_type):
        return self._get_accept_content_type() in content_type

    def _get_response_content_type(self):
        """ Standard content type is JSON. """
        return 'application/json'

    def _parse_request_body(self):
        """ Standard behavior is to expect JSON and to parse into self.args """
        # parse request body to json object
        try:
            self.args = json.loads(self.request.body)
        except Exception as e:
            self._exit_exception(e, status=400)
            self.log.debug(f'error while parsing {self.request.body} to JSON')

    def _validate_request(self):
        """
        Top level request parameter validation. Check for existence of request body
        and its parsability to a JSON object. Additionally, handle boolean string
        arguments in JSON string and convert them to Python booleans.
        All subclasses that expect a request body need to call this, preferably in the prepare method.
        """
        self._check_request_headers()
        # check for request body
        if not self.request.body:
            self._exit_error('No request body provided.', status=400)
        self._parse_request_body()
        # take care of strings representing booleans
        for k in self.args:
            if self.args[k] in ['true', 'True']:
                self.args[k] = True
            if self.args[k] in ['false', 'False']:
                self.args[k] = False

    def _finish(self, response_object):
        raise tornado.web.Finish(json.dumps(response_object))

    def _exit_success(self, response=None, status=200):
        """ Updates the usage dict on success and finalize the request. """
        # TODO: maybe add some stats here as request processing time or similar
        self.set_status(status)
        answer = {'state': 'success'}
        if response:
            answer['response'] = response
        self.log.debug(f'successful response ({status}), payload: {answer}')
        self._finish(answer)

    # error handling

    def _exit_no_route(self, method):
        self._exit_error(f"No {method} requests defined for this route.", status=405)

    def _exit_warn(self, response, warning_message, status=200):
        """ Response method when method returned only partly successfully. """
        self.set_status(status)
        resp = {
            'state': 'warning',
            'response': response,
            'message': warning_message
        }
        self.log.warning(f'incomplete response ({status}), payload: {resp}')
        self._finish(resp)

    def _exit_error(self, message, status=500):
        """ Update the usage dict on error and finalizes the request. """
        self.log.error(f'error {status} during response handling, reason: {message}')
        self.set_status(status)
        self._finish({'state': 'error', 'message': message})

    def _exit_exception(self, exception, status=500):
        """ Update the usage dict on exception and finalizes the request. """
        resp = self.create_exception_response(exception)
        self.set_status(status)
        self._log_exception(self.log, exception)
        self._finish(resp)

    @staticmethod
    def _get_traceback_string(tb):
        """ Construct string list from traceback object """
        return list(map(
            lambda x: f"{x.filename} @line {x.lineno}: {x.name}({x.line})",
            traceback.extract_tb(tb)))

    # convenience methods
    @staticmethod
    def call_service(service_url, payload, auth_token=None, method='POST', content_type='application/json',
                     timeout=20.):
        """ Call an external service, thin wrapper around request. """
        l = logging.getLogger(__name__)
        headers = {}
        if 'POST' in method or 'PUT' in method:
            headers.update({'Content-Type': content_type})
        if auth_token:
            headers['Authorization'] = f'Basic {auth_token.decode("utf-8")}'
        data = payload
        if content_type == 'application/json':
            data = json.dumps(payload)
        response = requests.request(method, service_url, headers=headers, data=data, timeout=timeout)
        if response.status_code == 204:
            # empty successful response
            return response.status_code, None
        response_object = None
        try:
            if response.headers['Content-Type'] == 'application/json':
                response_object = json.loads(response.text)
            else:
                response_object = response.text
        except Exception as e:
            l.error(response.text)
            GenericHandler._log_exception(l, e)
            response_object = GenericHandler.create_exception_response(e)
        finally:
            return response.status_code, response_object

    @staticmethod
    def _log_exception(logger, exception):
        tb_string = GenericHandler._get_traceback_string(exception.__traceback__)
        logger.error(type(exception).__name__ + ': ' + str(exception))
        logger.debug(tb_string)

    @staticmethod
    def create_exception_response(exception):
        return {
            'state': 'exception',
            'name': type(exception).__name__,
            'message': str(exception)
        }

    def _check_status(self, status, response):
        """ Checks the status of an internal call and exits with error if status is leq 400. """
        if status >= 400:
            self._exit_error(response, status=status)

    def _parameter_check(self, param_name):
        if param_name not in self.args:
            self._exit_error(f'Request body does not include mandatory parameter "{param_name}".', status=400)

    def _get_authentication_token(self):
        # try to extract from query string
        qs_token = self.get_query_argument('token', None)
        auth_token = None
        method = 'Bearer'
        if qs_token:
            auth_token = qs_token
        elif 'Authorization' in self.request.headers or 'Authentication' in self.request.headers:
            if 'Authorization' in self.request.headers:
                auth_header = self.request.headers['Authorization']
            else:
                auth_header = self.request.headers['Authentication']
            # check for Basic authentication, only this is supported (over SSL)
            # if not auth_header.startswith('Basic'):
            #     self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            #     self._exit_error('Authorization method is not Basic.', status=401)
            # this is most likely an API request
            # auth_string = self.request.headers['Authentication']
            method, auth_token = auth_header.split()
        else:
            # no Authorization header
            self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            self.set_header("WWW-Authenticate", "WWW-Authenticate Bearer")
            self._exit_error('Authorization header not set.', status=401)


        # cookie reading must be done within the webapp
        # else:
        #     # this is most likely a browser request
        #     self.auth_token = self.get_secure_cookie('sh_tornado_auth_token', max_age_days=3)
        return auth_token, method

    def _get_user_from_token(self, token):
        user_request_header = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        response = requests.get(self._get_oauth_user_endpoint_url(), headers=user_request_header)
        response_data = {}
        try:
            response_data = json.loads(response.text)
        except:
            pass
        current_user = None
        if 'data' in response_data:
            current_user = response_data['data']
        return current_user

    def _authenticate(self):
        if 'Bearer' in self.auth_method:
            # 1. get code
            self.authorize_redirect(
                redirect_uri=self.settings['auth_redirect_url'],
                client_id=self.settings['auth_client_id'],
            )
            # try to get user for this token
            if self.auth_token and not self.current_user:
                self.current_user = self._get_user_from_token(self.auth_token)
                if self.current_user:
                    return
        else: # this is Basic authorization
            # extract the sent authentication string and convert to byte array
            # method, b64enc = auth_header.split(' ')
            b64enc_bytes = bytes(self.auth_token, 'utf-8')
            # decode the byte string
            try:
                auth_plain = base64.b64decode(b64enc_bytes).decode('utf-8')
            except BinasciiError as e:
                self._exit_exception(e, status=400)
            # check if decoded byte string is correct token
            if self._check_token(auth_plain):
                return
        self._exit_error('Authorization failed, invalid token.', status=401)
