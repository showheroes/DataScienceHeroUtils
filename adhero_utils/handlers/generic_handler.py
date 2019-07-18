import tornado.web
import requests
import logging
import json
import traceback
import base64

class GenericHandler(tornado.web.RequestHandler):
    """ Generic request handler, defining standard pipeline of validating and processing a request. """

    def initialize(self):
        self.log = logging.getLogger(__name__)

    # request handling

    def prepare(self):
        """ Set usage dict and authenticate """
        self.usage = self.get_usage()
        # TODO authentication is still crude, think of something more elaborate
        self._authenticate()

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

    def _validate_request(self):
        """
        Top level request parameter validation. Check for existence of request body
        and its parsability to a JSON object. Additionally, handle boolean string
        arguments in JSON string and convert them to Python booleans.
        All subclasses that expect a request body need to call this, preferably in the prepare method.
        """
        if not 'Content-Type' in self.request.headers or self.request.headers['Content-Type'] != 'application/json':
            self.set_status(400, reason="Not a JSON request.")
            self._exit_error("Not a JSON request, be sure to set request headers appropriately.")
        # check for request body
        if not self.request.body:
            self.set_status(400, reason='No request body.')
            self._exit_error('No request body provided.')
        # parse request body to json object
        try:
            self.args = json.loads(self.request.body)
        except Exception as e:
            self.set_status(400, reason='Malformed JSON.')
            self._exit_exception(e)

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
        self.set_status(405, reason=f"No {method} requests defined for this route.")
        self._exit_error(f"No {method} requests defined for this route.")

    def _exit_error(self, message):
        """ Update the usage dict on error and finalizes the request. """
        l = logging.getLogger(__name__)
        l.error(message)
        self._finish({'state' : 'error', 'message' : message})

    def _exit_exception(self, exception):
        """ Update the usage dict on exception and finalizes the request. """
        resp = {
            'state' : 'exception',
            'message' : exception.args
        }
        tb_string = self._get_traceback_string(exception.__traceback__)
        if 'debug' in self.application.settings and self.application.settings['debug']:
            resp.update({'traceback' : tb_string})
        l = logging.getLogger(__name__)
        l.error(exception.args)
        l.error(tb_string)
        self._finish(resp)

    @staticmethod
    def _get_traceback_string(tb):
        """ Construct string list from traceback object """
        return list(map(
            lambda x : f"{x.filename} @line {x.lineno}: {x.name}({x.line})",
            traceback.extract_tb(tb)))

    # convenience methods
    @staticmethod
    def call_service(service_url, payload, auth_token=None, method='POST'):
        """ Call an external service, thin wrapper around request. """
        headers = {'Content-Type':'application/json'}
        if auth_token:
            headers['Authentication'] = f'Basic {auth_token.decode("utf-8")}'
        response = requests.request(method, service_url, headers=headers, data = json.dumps(payload), timeout=20.)
        return response.status_code, json.loads(response.text) if response.text else None

    def _check_status(self, status, response):
        """ Checks the status of an internal call and exits with error if status is leq 400. """
        if status >= 400:
            self.set_status(status)
            self._exit_error(response.text)

    def _parameter_check(self, param_name):
        if not param_name in self.args:
            self.set_status(400, f'Parameter "{param_name}" is missing.')
            self._exit_error(f'Request body does not include mandatory paramter "{param_name}".')

    def _authenticate(self):
        # check authentication
        if 'auth_token' in self.settings:
            if base64.b64decode(self.settings['auth_token']) == bytes('adhero_analysis_demo', 'utf-8'):
                return
        if not 'Authentication' in self.request.headers:
            self.set_status(401, reason='Authentication header not set.')
            self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            self._exit_error('Authentication header not set.')

        auth_header = self.request.headers['Authentication']
        if not auth_header.startswith('Basic'):
            self.set_status(401, reason='Only Basic authentication is supported.')
            self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            self._exit_error('Authentication method is not Basic.')

        method, b64enc = auth_header.split(' ')
        b64enc_bytes = bytes(b64enc, 'utf-8')
        auth_plain = base64.b64decode(b64enc_bytes)
        if auth_plain != bytes('adhero_analysis_demo', 'utf-8'):
            self.set_status(401, reason='Authentication failed.')
            self.set_header("WWW-Authenticate", "WWW-Authenticate Basic")
            self._exit_error('Authentication failed, invalid authentication token.')

        self.settings['auth_token'] = b64enc_bytes
