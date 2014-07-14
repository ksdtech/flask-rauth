# -*- coding: utf-8 -*-
'''
    flask.ext.rauth
    ~~~~~~~~~~~~~~~

    Adds OAuth 1.0/a, 2.0, and Ofly consumer support for Flask.

    Flask-Rauth is a fork of Armin Ronacher's Flask-OAuth.
    :copyright: (c) 2010 by Armin Ronacher.
    :copyright: (c) 2012 by Joel Verhagen.
    :license: BSD, see LICENSE for more details.
'''
from functools import wraps
from urlparse import urljoin
from flask import request, session, redirect, current_app
from rauth.service import OAuth2Service, OAuth1Service, OflyService
from rauth.utils import parse_utf8_qsl
from json import loads as parse_json

# specified by the OAuth 2.0 spec
# http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1.4
ACCESS_DENIED = 'access_denied'

class RauthServiceMixin(object):
    '''
    A mixin used to help glue Flask and `rauth` together. **You should not
    initialize this class on your own.** Instead, it will be initialized by one
    of the service objects above.

    :param base_url: A base URL value which, if provided, will be joined
        with the URL passed to requests made on this object.
    '''
    def __init__(self, app, base_url):
        # TODO: app is not actually used in any way.
        self.app = app
        if app is not None:
            self.init_app(app)

        self.base_url = base_url
        self.tokengetter_f = None

    def init_app(self, app):
        '''
        Initializes the application with this object as an extension.

        This simply ensures that there are `config` entries for keys generated
        by :func:`_consumer_key_config` and :func:`_consumer_secret_config`,
        i.e. ``(NAME)_CONSUMER_KEY`` and ``(NAME)_CONSUMER_SECRET``.

        :param app: A Flask application object.
        '''
        # the name attribute will be set by a rauth service
        if isinstance(self, OAuth1Service):
            app.config.setdefault(self._consumer_key_config())
            app.config.setdefault(self._consumer_secret_config())
        elif isinstance(self, OAuth2Service):
            app.config.setdefault(self._client_id_config())
            app.config.setdefault(self._client_secret_config())
        elif isinstance(self, OflyService):
            app.config.setdefault(self._app_id_config())
            app.config.setdefault(self._app_secret_config())

    def tokengetter(self, f):
        '''
        The tokengetter decorator used to provide a function that will return
        the required token before making a request.
        '''
        self.tokengetter_f = f
        return f

    def _expand_url(self, url):
        # prepend the base base_url, if we have it
        if self.base_url is not None:
            url = urljoin(self.base_url, url)
        return url

    def _session_key(self, suffix):
        return '%s_%s_%s' % (self.name, self.__class__.__name__, suffix)

    @property
    def consumer_key(self):
        '''
        Returns the consumer_key for this object. The following method is used
        to determine what the consumer_key is:

        1. A `static_consumer_key`, set by passing a `consumer_key` to the
            constructor.
        2. The `consumer_key` set in the config of an app passed to the
            constructor. The application config key is based on the name
            passed to the constructor. See :func:`init_app` for more
            information.
        3. The `consumer_key` set in the config of the Flask `current_app`.
        '''
        if self.static_consumer_key is not None:
            # if a consumer key was provided in the constructor, default to that
            return self.static_consumer_key
        elif self.app is not None and self._consumer_key_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._consumer_key_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._consumer_key_config(), None)

    @consumer_key.setter
    def consumer_key(self, consumer_key):
        self.static_consumer_key = consumer_key

    @property
    def consumer_secret(self):
        '''
        Returns the consumer_secret for this object. A method analogous to that
        of `consumer_key` is used to find the value.
        '''
        if self.static_consumer_secret is not None:
            # if a consumer secret was provided in the constructor, default to that
            return self.static_consumer_secret
        elif self.app is not None and self._consumer_secret_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._consumer_secret_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._consumer_secret_config(), None)

    @consumer_secret.setter
    def consumer_secret(self, consumer_secret):
        self.static_consumer_secret = consumer_secret

    def _consumer_key_config(self):
        return '%s_CONSUMER_KEY' % (self.name.upper(),)

    def _consumer_secret_config(self):
        return '%s_CONSUMER_SECRET' % (self.name.upper(),)

    @property
    def client_id(self):
        '''
        Returns the client_id for this object. A method analogous to that
        of `consumer_key`.
        '''
        if self.static_client_id is not None:
            # if a client was provided in the constructor, default to that
            return self.static_client_id
        elif self.app is not None and self._client_id_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._client_id_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._client_id_config(), None)

    @client_id.setter
    def client_id(self, client_id):
        self.static_client_id = client_id

    @property
    def client_secret(self):
        '''
        Returns the client_secret for this object. A method analogous to that
        of `client_id`.
        '''
        if self.static_client_secret is not None:
            # if a consumer secret was provided in the constructor, default to that
            return self.static_client_secret
        elif self.app is not None and self._client_secret_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._client_secret_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._client_secret_config(), None)

    @client_secret.setter
    def client_secret(self, client_secret):
        self.static_client_secret = client_secret

    def _client_id_config(self):
        return '%s_CLIENT_ID' % (self.name.upper(),)

    def _client_secret_config(self):
        return '%s_CLIENT_SECRET' % (self.name.upper(),)

    @property
    def app_id(self):
        '''
        Returns the app_id for this object. A method analogous to that
        of `consumer_key`.
        '''
        if self.static_app_id is not None:
            # if a client was provided in the constructor, default to that
            return self.static_app_id
        elif self.app is not None and self._app_id_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._app_id_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._app_id_config(), None)

    @app_id.setter
    def app_id(self, app_id):
        self.static_app_id = app_id

    @property
    def app_secret(self):
        '''
        Returns the app_secret for this object. A method analogous to that
        of `app_id`.
        '''
        if self.static_app_secret is not None:
            # if a consumer secret was provided in the constructor, default to that
            return self.static_app_secret
        elif self.app is not None and self._app_secret_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._app_secret_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._app_secret_config(), None)

    @client_secret.setter
    def client_secret(self, client_secret):
        self.static_client_secret = client_secret

    def _app_id_config(self):
        return '%s_APP_ID' % (self.name.upper(),)

    def _app_secret_config(self):
        return '%s_APP_SECRET' % (self.name.upper(),)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)

class RauthOAuth2(OAuth2Service, RauthServiceMixin):
    '''
    Encapsulates OAuth 2.0 interaction to be easily integrated with Flask.

    This class inherits :class:`rauth.service.OAuth2Service` and
    :class:`RauthServiceMixin`.

    :param app: See :class:`RauthServiceMixin`.
    :param base_url: See :class:`RauthServiceMixin`.
    :param consumer_key: A static consumer key to use with this service.
        Supplying this argument will mean any consumer keys found in Flask
        application config will be ignored.
    :param consumer_secret: A static consumer secret to use with this service.
        Supplying this argument will mean any consumer secrets found in Flask
        application config will be ignored.
    :param kwargs: Any arguments that can be passed to
        :class:`rauth.OAuth2Service`.
    '''
    def __init__(self, app=None, base_url=None, client_id=None, client_secret=None, **kwargs):
        RauthServiceMixin.__init__(self, app=app, base_url=base_url)
        OAuth2Service.__init__(self, client_id=client_id, client_secret=client_secret,
                               base_url=base_url, **kwargs)

    def authorize(self, callback, **authorize_params):
        '''
        Begins the OAuth 2.0 authorization process for this service.

        :param callback: The **required** absolute URL that will be
            redirected to by the OAuth 2.0 endpoint after authorization is
            complete.
        :param authorize_params: Query parameters to be passed to authorization,
            prompt, addition to the `redirect_uri`. One common example is
            `scope`.
        '''
        # save the redirect_uri in the session
        session[self._session_key('redirect_uri')] = callback
        authorize_params['redirect_uri'] = callback
        #authorize_params['response_type'] = 'code'
        return redirect(self.get_authorize_url(**authorize_params))

    def authorized_handler(self, method='POST', grant_type='authorization_code', decoder=parse_json):
        '''
        The decorator to assign a function that will be called after
        authorization is complete. By default, a `POST` request is used to
        fetch the access token. If you need to send a `GET` request, use the
        ``authorized_handler(method='GET')`` to do so.

        It should be a route that takes two parameters: `response` and
        `access_token`.

        If `response` is ``access_denied``, then the user denied access to
            his/her information.
        '''
        def create_authorized_handler(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                resp = access_token = None
                if 'error' in request.args and request.args['error'] == ACCESS_DENIED:
                    resp = ACCESS_DENIED
                elif 'code' in request.args:
                    # GET requests need the data put under 'params' and all others
                    # need to be under 'data'
                    key = 'data'
                    if method == 'GET':
                        key='params'
                    gat_kwargs = {
                        key: {
                            'code': request.args['code'],
                            'grant_type': grant_type,
                            'redirect_uri': session.pop(self._session_key('redirect_uri'), None)
                        }
                    }
                    access_token = self.get_access_token(method=method, decoder=decoder, **gat_kwargs)
                    resp = self.get_session(access_token)
                return f(*((resp, access_token) + args), **kwargs)
            return decorated
        return create_authorized_handler

    def request(self, method, url, access_token=None, **kwargs):
        '''
        Make a request using an `access_token` obtained via the
            :func:`authorized_handler`.

        If no access_token is provided and a
        :func:`RauthServiceMixin.tokengetter` **was** provided, the
        :func:`RauthServiceMixin.tokengetter` will be called.

        :param method: Same as :func:`rauth.OAuth2Service.request`.
        :param url: Same as :func:`rauth.OAuth2Service.request`, except when a
            `base_url` was provided to the constructor, in which case the URL
            should be any valid endpoint after being :func:`urljoin` ed with
            the `base_url`.
        :param access_token: The `access_token` required to make requests
            against this service.
        :param kwargs: Any `kwargs` that can be passed to
            :func:`OAuth2Session.request`.
        '''
        url = self._expand_url(url)

        if access_token is None and self.tokengetter_f is not None:
            access_token = self.tokengetter_f()
        
        # get a session and call the request method
        return self.get_session(access_token).request(method, url, **kwargs)

class RauthOAuth1(OAuth1Service, RauthServiceMixin):
    '''
    Encapsulates OAuth 1.0a interaction to be easily integrated with Flask.

    This class inherits :class:`rauth.service.OAuth1Service` and
    :class:`RauthServiceMixin`.

    See :class:`RauthOAuth2` for analogous details.
    '''
    def __init__(self, app=None, base_url=None, consumer_key=None, consumer_secret=None, **kwargs):
        RauthServiceMixin.__init__(self, app=app, base_url=base_url)
        OAuth1Service.__init__(self, consumer_key=consumer_key, consumer_secret=consumer_secret,
                               base_url=base_url, **kwargs)

    def authorize(self, callback, **request_params):
        '''
        Begins the OAuth 1.0a authorization process for this service.

        :param callback: The **required** absolute URL that will be
            redirected to by the OAuth 1.0 endpoint after authorization is
            complete.
        :param request_params: Query parameters to be passed to the request,
            token endpoint, in addition to the `callback`. One common example
            is `scope`.
        '''
        # fetch the request_token (token and secret 2-tuple) and convert it to a dict
        request_params['oauth_callback'] = callback
        request_token = self.get_request_token(data=request_params)

        # save the request_token in the session
        session[self._session_key('request_token')] = request_token

        # pass the token and any user-provided parameters
        return redirect(self.get_authorize_url(request_token[0]))

    def authorized_handler(self, method='POST'):
        '''
        The handler should expect two arguments: `session` and `oauth_token`.
        By default, a `POST` request is used to fetch the access token. If you
        need to send a `GET` request, use the
        ``authorized_handler(method='GET')`` to do so.

        If `session` is ``None`` then the user *most-likely* denied access
            to his/her information. Since OAuth 1.0a does not specify a
            standard query parameter to specify that the user denied the
            authorization, you will need to figure out how the endpoint that
            your are interacting with delineates this edge-case.
        '''
        def create_authorized_handler(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                s = token = None
                request_token, request_token_secret = session.pop(self._session_key('request_token'))
                if 'oauth_verifier' in request.args:
                    token = self.get_access_token(
                        request_token,
                        request_token_secret,
                        method=method,
                        data={'oauth_verifier': request.args['oauth_verifier']}
                    )
                    s = self.get_session(token)
                return f(*((s, token) + args), **kwargs)
            return decorated
        return create_authorized_handler


    def request(self, method, url, oauth_token=None, **kwargs):
        '''
        Make a request using an `oauth_token` obtained via the
            :func:`authorized_handler`.
        '''
        url = self._expand_url(url)

        if oauth_token is None and self.tokengetter_f is not None:
            oauth_token = self.tokengetter_f()

        # get a session and make the request
        return self.get_session(oauth_token).request(self, method, url, **kwargs)


class RauthOfly(OflyService, RauthServiceMixin):
    '''
    Encapsulates Ofly interaction to be easily integrated with Flask.

    This class inherits :class:`rauth.service.OflyService` and
    :class:`RauthServiceMixin`.

    See :class:`RauthOAuth2` for analogous details.
    '''
    def __init__(self, app=None, base_url=None, consumer_key=None, consumer_secret=None, **kwargs):
        RauthServiceMixin.__init__(self, app=app, base_url=base_url)
        OflyService.__init__(self, consumer_key=consumer_key, consumer_secret=consumer_secret,
                             base_url=base_url, **kwargs)

    def authorize(self, callback, **authorize_params):
        '''
        Begins the Ofly authorization process for this service.

        :param callback: The **required** absolute URL that will be
            redirected to by the Ofly endpoint after authorization is
            complete.
        :param authorize_params: Query parameters to be passed to the request,
            token endpoint, in addition to the `callback`.
        '''
        # Ofly web authentication (== "app authentication" == "seamless sign-in") requires a redirect_uri value

        # pass the callback and any user-provided parameters
        return redirect(self.get_authorize_url(redirect_uri=callback, **authorize_params))

    def authorized_handler(self, method='POST'):
        '''
        The handler should expect two arguments: `response` and `oflyUserid`.
        The `method` parameter is unused.

        If `response` is ``access_denied``, then the user denied access to
            his/her information.
        '''
        def create_authorized_handler(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                resp = oflyUserid = None
                if 'oflyUserid' in request.args:
                    if request.args['oflyUserid'] == 'no-grant':
                        resp = ACCESS_DENIED
                    else:
                        resp = {
                            'oflyUserid': request.args['oflyUserid'],
                            'oflyAppId': request.args.get('oflyAppId'),
                            'oflyUserEmail': request.args.get('oflyUserEmail')
                        }

                        oflyUserid = request.args['oflyUserid']

                return f(*((resp, oflyUserid) + args), **kwargs)
            return decorated
        return create_authorized_handler


    def request(self, method, url, oflyUserid=None, **kwargs):
        '''
        Make a request using an `oflyUserid` obtained via the
            :func:`authorized_handler`.
        '''
        url = self._expand_url(url)

        if oflyUserid is None and self.tokengetter_f is not None:
            oflyUserid = self.tokengetter_f()

        # add in the access_token
        if 'params' not in kwargs:
            kwargs['params'] = {'oflyUserid': oflyUserid}
        elif 'oflyUserid' not in kwargs['params']:
            # TODO: handle if the user sends bytes -> properly append 'oflyUserid'
            kwargs['params']['oflyUserid'] = oflyUserid

        # get session and make the request
        return self.get_session(oflyUserid).request(self, method, url, **kwargs)
    