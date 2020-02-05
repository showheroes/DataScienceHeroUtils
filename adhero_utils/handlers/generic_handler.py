import tornado.web
import requests
import logging
import json
import traceback
import base64
from binascii import Error as BinasciiError
import time

class GenericHandler(tornado.web.RequestHandler):
    """ Generic request handler, defining standard pipeline of validating and processing a request. """

    def initialize(self):
        self.log = logging.getLogger(__name__)

    # request handling

    def prepare(self):
        """ Set usage dict and authenticate """
        self.start_time = time.time_ns()
        self.usage = self.get_usage()
        # set standarad response content type
        self.set_header('Content-Type', self._get_response_content_type())
        # TODO authentication is still crude, think of something more elaborate
        self._authenticate()

    def on_finish(self):
        self.end_time = time.time_ns()
        self.elapsed_time_ms = (self.end_time - self.start_time)/1000000.
        self._collect_statistics()

    def _collect_statistics(self):
        pass

    def get(self):
        """ Standard response for GET requests 405 with is the usage string. """
        self._exit_no_route('GET')

    def post(self):
        """ POST requests check request parameters and execute _process_request """
        self._exit_no_route('POST')

    def put(self):
        """ PUT request standard response."""
        self._exit_no_route('PUT')

    def delete(self):
        """ DELETE standard response """
        self._exit_no_route('DELETE')

    def get_usage(self):
        return {}

    def _check_request_headers(self):
        """ Checks the request headers for the expected content type """
        if not 'Content-Type' in self.request.headers or self.request.headers['Content-Type'] != self._get_accept_content_type():
            self._exit_error(f"Unexpected content type: {self.request.headers['Content-Type']}, be sure to set request headers appropriately.", status = 400)

    def _get_accept_content_type(self):
        """ Standard acceptable content type. """
        return 'application/json'

    def _get_response_content_type(self):
        """ Standard content type is JSON. """
        return 'application/json'

    def _parse_request_body(self):
        """ Standard behavior is to expect JSON and to parse into self.args """
        # parse request body to json object
        try:
            self.args = json.loads(self.request.body)
        except Exception as e:
            self._exit_exception(e, status = 400)
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
            self._exit_error('No request body provided.', status = 400)
        self._parse_request_body()
        # take care of strings representing booleans
        for k in self.args:
            if self.args[k] in ['true', 'True']:
                self.args[k] = True
            if self.args[k] in ['false', 'False']:
                self.args[k] = False

    def _finish(self, response_object):
        raise tornado.web.Finish(json.dumps(response_object))

    def _exit_success(self, response):
        """ Updates the usage dict on success and finalize the request. """
        # TODO: maybe add some stats here as request processing time or similar
        self._finish({
            'state' : 'success',
            'response' : response
        })

    # error handling

    def _exit_no_route(self, method):
        self._exit_error(f"No {method} requests defined for this route.", status = 405)

    def _exit_warn(self, response, warning_message, status = 200):
        """ Response method when method returned only partly successfully. """
        self.set_status(status)
        resp = {
            'state' : 'warning',
            'response' : response,
            'message' : warning_message
        }
        self._finish(resp)

    def _exit_error(self, message, status = 500):
        """ Update the usage dict on error and finalizes the request. """
        l = logging.getLogger(__name__)
        l.error(message)
        self.set_status(status)
        self._finish({'state' : 'error', 'message' : message})

    def _exit_exception(self, exception, status = 500):
        """ Update the usage dict on exception and finalizes the request. """
        resp = self.create_exception_response(exception)
        self.set_status(status)
        self._log_exception(self.log, exception)
        self._finish(resp)

    @staticmethod
    def _get_traceback_string(tb):
        """ Construct string list from traceback object """
        return list(map(
            lambda x : f"{x.filename} @line {x.lineno}: {x.name}({x.line})",
            traceback.extract_tb(tb)))

    # convenience methods
    @staticmethod
    def call_service(service_url, payload, auth_token=None, method='POST', content_type = 'application/json', timeout=20.):
        """ Call an external service, thin wrapper around request. """
        l = logging.getLogger(__name__)
        headers = {}
        if 'POST' in method or 'PUT' in method:
            headers.update({'Content-Type':content_type})
        if auth_token:
            headers['Authentication'] = f'Basic {auth_token.decode("utf-8")}'
        data = payload
        if content_type == 'application/json':
            data = json.dumps(payload)
        response = requests.request(method, service_url, headers=headers, data=data, timeout=timeout)
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
            'state' : 'exception',
            'name' : type(exception).__name__,
            'message' : str(exception)
        }

    def _check_status(self, status, response):
        """ Checks the status of an internal call and exits with error if status is leq 400. """
        if status >= 400:
            self._exit_error(response, status = status)

    def _parameter_check(self, param_name):
        if not param_name in self.args:
            self._exit_error(f'Request body does not include mandatory parameter "{param_name}".', status = 400)

    def _authenticate(self):
        # check for Authentication header
        if not 'Authentication' in self.request.headers:
            self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            self._exit_error('Authentication header not set.', status = 401)

        auth_header = self.request.headers['Authentication']
        # check for Basic authentication, only this is supported (over SSL)
        if not auth_header.startswith('Basic'):
            self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            self._exit_error('Authentication method is not Basic.', status = 401)

        # extract the sent authentication string and convert to byte array
        method, b64enc = auth_header.split(' ')
        b64enc_bytes = bytes(b64enc, 'utf-8')
        # decode the byte string
        try:
            auth_plain = base64.b64decode(b64enc_bytes).decode('utf-8')
        except BinasciiError as e:
            self._exit_exception(e, status = 400)
        # check if decoded byte string is correct token
        if self._check_token(auth_plain):
            return
        self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
        self._exit_error('Authentication failed, invalid authentication token.', status = 401)
