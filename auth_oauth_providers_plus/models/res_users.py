import logging

import requests
from requests.exceptions import RequestException
from odoo import api, fields, models, _
from odoo.http import request
from odoo.addons.auth_signup.models.res_partner import SignupError


_logger = logging.getLogger(__name__)

class ResUsers(models.Model):
    _inherit = 'res.users'

    def _auth_oauth_rpc(self, endpoint, access_token):
        """ Override _auth_oauth_rpc to add logging and debug response """
        _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Making request to %s with access_token: %s", endpoint, access_token)

        try:
            use_auth_header = self.env['ir.config_parameter'].sudo().get_param('auth_oauth.authorization_header')
            _logger.info("🔹 [_auth_oauth_rpc] ResUsers: use_auth_header from config: %s", use_auth_header)
        except Exception as e:
            _logger.exception("🔹 [_auth_oauth_rpc] ResUsers: request to database failed: %s", e)
            return {'error': e}

        headers = {}
        params = {}

        if use_auth_header:
            headers = {'Authorization': f'Bearer {access_token}'}
            _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Using Authorization header")
        else:
            params = {'access_token': access_token}
            _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Using access_token parameter")

        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=10)
            _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Response status: %s", response.status_code)
            _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Response headers: %s", response.headers)
           # _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Response content: %s", response.text)

            if response.ok:
                return response.json()

            # Handle authentication challenge errors
            auth_challenge = parse_auth(response.headers.get("WWW-Authenticate"))
            if auth_challenge and auth_challenge.type == 'bearer' and 'error' in auth_challenge:
                _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Auth challenge error: %s", auth_challenge)
                return dict(auth_challenge)

            _logger.error("🔹 [_auth_oauth_rpc] ResUsers: Unexpected error in validation: invalid_request")
            return {'error': 'invalid_request'}

        except requests.RequestException as e:
            _logger.info("🔹 [_auth_oauth_rpc] ResUsers: Request failed due to exception: %s", e)
            return {'error': 'connection_failed'}


    @api.model
    def _auth_oauth_validate(self, provider, access_token):
    # return the validation data corresponding to the access token
    # Override _auth_oauth_validate to ensure proper validation #
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)

        _logger.info("🔹 [_auth_oauth_validate] ResUsers: Validating token at %s with access_token: %s", oauth_provider.validation_endpoint, access_token)

        validation = self._auth_oauth_rpc(oauth_provider.validation_endpoint, access_token)

        _logger.info("🔹 [_auth_oauth_validate] ResUsers: Validation response: %s", validation)

        if validation.get("error"):
            _logger.info("🔹 [_auth_oauth_validate] ResUsers: Error in validation: %s", validation['error'])
            raise Exception(validation['error'])

        if oauth_provider.data_endpoint and ('sub' not in validation or 'email' not in validation):
            _logger.info("🔹 [_auth_oauth_validate] ResUsers: Fetching extra user data from %s", oauth_provider.data_endpoint)
            _logger.info("🔹 [_auth_oauth_validate] ResUsers: access_token %s", access_token)
            try:
                data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token)
                try:
                    validation.update(data)
                except Exception as e:
                    _logger.info("🔹 [_auth_oauth_validate] ResUsers: error in validation.update(data) %s", e)
            except Exception as e:
                _logger.info("🔹 [_auth_oauth_validate] ResUsers: Error in getting data from _auth_oauth_rpc: %s", e)


        # 🟡 Log the entire OIDC response for debugging (careful with sensitive data)
        _logger.info("🔹 [_auth_oauth_validate] ResUsers:OIDC Validation Response: %s", validation)

        # 🟠 Log specific OIDC claims: 'sub' and 'email' if available
        if 'sub' in validation:
            _logger.info("🔹 [_auth_oauth_validate] ResUsers:OIDC Subject (sub): %s", validation.get('sub'))
        else:
            _logger.warning("🔹 [_auth_oauth_validate] ResUsers:OIDC: No 'sub' claim found in response")

        if 'email' in validation:
           _logger.info("🔹 [_auth_oauth_validate] ResUsers:OIDC Email: %s", validation.get('email'))
        else:
           _logger.info("🔹 [_auth_oauth_validate] ResUsers:OIDC: No 'email' claim found in response")

        # unify subject key, pop all possible and get most sensible. When this
        # is reworked, BC should be dropped and only the `sub` key should be
        # used (here, in _generate_signup_values, and in _auth_oauth_signin)
        subject = next(filter(None, [
            validation.pop(key, None)
            for key in [
                'sub',  # standard OpenID Connect (Nextcloud, Keycloak, AuthO, Google....)
                'id',  # google v1 userinfo, facebook opengraph
                'user_id' # google tokeninfo, odoo (tokeninfo)
            ]
        ]), None)

        if not subject:
            _logger.error("🔹 [_auth_oauth_validate] ResUsers: No subject identifier found in response")
            raise AccessDenied("Missing subject identity")



        validation['user_id'] = subject

        _logger.info("🔹 [_auth_oauth_validate] ResUsers: Successful validation with user_id: %s", subject)

        return validation


    @api.model
    def _generate_signup_values(self, provider, validation, params):
        """ Generate user signup values from OpenID Connect """
        oauth_uid = validation.get('sub') or validation.get('user_id')  # Ensure we get 'sub' from OpenID
        if not oauth_uid:
            raise AccessDenied("🔹 [_generate_signup_values] ResUsers: Missing subject identifier (sub)")

        email = validation.get('email')
        email_verified = validation.get('email_verified', False)

        # Ensure email is verified
        if not email or not email_verified:
            raise AccessDenied("🔹 [_generate_signup_values] ResUsers:  Email is missing or not verified by the provider.")

        name = validation.get('name', email)
        username = validation.get('preferred_username', email)  # OpenID often includes a preferred username

        _logger.info('🔹 [_generate_signup_values] ResUsers: Signup values from provider, validation and params ')
        _logger.info('🔹 [_generate_signup_values] ResUsers: oauth_uid: %s', oauth_uid)
        _logger.info('🔹 [_generate_signup_values] ResUsers: email: %s', email)
        _logger.info('🔹 [_generate_signup_values] ResUsers: email_verified: %s', email_verified)
        _logger.info('🔹 [_generate_signup_values] ResUsers: name: %s', name)
        _logger.info('🔹 [_generate_signup_values] ResUsers: username: %s', username)
        _logger.info('🔹 [_generate_signup_values] ResUsers: oauth_provider_id: %s', provider)
        _logger.info('🔹 [_generate_signup_values] ResUsers: oauth_access_token: %s', params['access_token'])

        return {
            'name': name,
            'login': username,
            'email': email,
            'oauth_provider_id': provider,
            'oauth_uid': oauth_uid,
            'oauth_access_token': params['access_token'],
            'active': True,
        }


    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param validation: result of validation of access token (dict)
            :param params: oauth parameters (dict)
            :return: user login (str)
            :raise: AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        _logger.info('🔹 [_auth_oauth_signin] ResUsers: SignIn')
        _logger.info('🔹 [_auth_oauth_signin] ResUsers: oauth_uid: %s', validation['user_id'])
        _logger.info('🔹 [_auth_oauth_signin] ResUsers: provider: %s', provider)
        _logger.info('🔹 [_auth_oauth_signin] ResUsers: validation: %s', validation)
        _logger.info('🔹 [_auth_oauth_signin] ResUsers: params: %s', params)


        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        _logger.info('🔹 [_auth_oauth_signin] ResUsers: OAuth Provider Type: %s', oauth_provider.provider_type)

        # ✅ Use different fields based on provider type
        if oauth_provider.provider_type == 'nextcloud':
           oauth_uid = validation.get('email')
           _logger.info('🔹 [_auth_oauth_signin] ResUsers: Nextcloud detected, using name/email as oauth_uid: %s', oauth_uid)
        else:
           oauth_uid = validation.get('user_id')
           _logger.info('🔹 [_auth_oauth_signin] ResUsers: Using user_id as oauth_uid: %s', oauth_uid)
           oauth_uid = validation['user_id']
        try:
            oauth_user = self.search([("oauth_uid", "=", oauth_uid), ('oauth_provider_id', '=', provider)])
            _logger.info('🔹 [_auth_oauth_signin] ResUsers: oauth_user: %s', oauth_user)
            _logger.info('🔹 [_auth_oauth_signin] ResUsers: oauth_access_token: %s', params['access_token'])
            if not oauth_user:
                raise AccessDenied()
            assert len(oauth_user) == 1
            oauth_user.write({'oauth_access_token': params['access_token']})
            return oauth_user.login
        except AccessDenied as access_denied_exception:
            if self.env.context.get('no_user_creation'):
                return None
            state = json.loads(params['state'])
            token = state.get('t')
            values = self._generate_signup_values(provider, validation, params)
            try:
                login, _ = self.signup(values, token)
                return login
            except (SignupError, UserError):
                raise access_denied_exception

    @api.model
    def auth_oauth(self, provider, params):
        # Advice by Google (to avoid Confused Deputy Problem)
        # if validation.audience != OUR_CLIENT_ID:
        #   abort()
        # else:
        #   continue with the process

        access_token = params.get('access_token')
        validation = self._auth_oauth_validate(provider, access_token)
        _logger.info('🔹 [auth_oauth] ResUsers: auth_oauth')
        _logger.info('🔹 [auth_oauth] ResUsers: login')
        _logger.info('🔹 [auth_oauth] ResUsers: provider: %s', provider)
        _logger.info('🔹 [auth_oauth] ResUsers: validation: %s', validation)
        _logger.info('🔹 [auth_oauth] ResUsers: params: %s', params)
        # retrieve and sign in user
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)

    def _check_credentials(self, credential, env):
        try:
            return super()._check_credentials(credential, env)
        except AccessDenied:
            if not (credential['type'] == 'oauth_token' and credential['token']):
                raise
            passwd_allowed = env['interactive'] or not self.env.user._rpc_api_keys_only()
            if passwd_allowed and self.env.user.active:
                res = self.sudo().search([('id', '=', self.env.uid), ('oauth_access_token', '=', credential['token'])])
                if res:
                    return {
                        'uid': self.env.user.id,
                        'auth_method': 'oauth',
                        'mfa': 'default',
                    }
            raise

    def _get_session_token_fields(self):
        return super(ResUsers, self)._get_session_token_fields() | {'oauth_access_token'}



    @api.model
    def _signup_create_user(self, values):
        """ Override to check if an email (login) already exists and log debug information """
        _logger.info("🔹 [_signup_create_user] ResUsers: Attempting to create a new user with values: %s", values)

        if 'login' in values:
            existing_user = self.sudo().search([('login', '=', values['login'])])
            if existing_user:
                _logger.info("🔹 [_signup_create_user] ResUsers:  Signup failed - User with email %s already exists!", values['login'])
                raise SignupError(_(' A user with email %s already exists, so we cannot create a user with the given OAuth2 provider.') % values['login'])

        try:
            user = super(ResUsers, self)._signup_create_user(values)
            _logger.info("🔹 [_signup_create_user] ResUsers:  User %s successfully created!", user.login)
            return user
        except Exception as e:
            _logger.info("🔹 [_signup_create_user] ResUsers:  Unexpected error during user creation: %s", str(e))
            raise UserError(_("  User creation failed due to an internal error. Please check logs."))

