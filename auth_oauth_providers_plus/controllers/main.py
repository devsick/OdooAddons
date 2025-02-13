import base64
import functools
import json
import logging
import os


from odoo import api, http, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied
from odoo.http import request, Response
from odoo import registry as registry_get
from odoo.tools.misc import clean_context

import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest

from odoo.addons.auth_oauth.controllers.main import OAuthLogin as oauth_login
from odoo.addons.auth_oauth.controllers.main import OAuthController as oauth_controller
from odoo.addons.web.controllers.utils import ensure_db, _get_login_redirect_url


#added
_logger = logging.getLogger(__name__)

# Added for better error handling
from odoo.exceptions import UserError

class OAuthLogin(oauth_login):

    def list_providers(self):
        try:
            providers = request.env['auth.oauth.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            providers = []

        for provider in providers:
            # Ensure client_secret is available
            client_secret = provider.get('client_secret', None)  # Use .get() to avoid KeyError

            return_url = request.httprequest.url_root + 'auth_oauth/signin'
            state = self.get_state(provider)

            # Get the response type based on the user's selection
            if provider.get("flow_type") == "implicit":
                response_type = "id_token token"
            elif provider.get("flow_type") == "authorization_code":
                response_type = "code"
            elif provider.get("flow_type") == "hybrid":
                response_type = "code id_token"
            else:
                response_type = "authorization_code"  # Default to code flow
            params = dict(
                response_type=response_type,
                client_id=provider['client_id'],
                redirect_uri=return_url,
                scope=provider['scope'],
                state=json.dumps(state),
            )

            # Add nonce only if OpenID is enabled
            if provider.get("is_openid"):
                 params["nonce"] = base64.urlsafe_b64encode(os.urandom(16)).decode()

            # Include the client_secret in the params
            if client_secret:
                params['client_secret'] = client_secret

            # Update the OAuth2 auth_link with the correct parameters
            provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.urls.url_encode(params))

            _logger.debug('🔹 [list_providers] OAuthLogin: List_Providers in auth_oauth_advanced_OAtuhLogin ')
            _logger.debug('🔹 [list_providers] OAuthLogin: response_type: %s', response_type)
            _logger.debug('🔹 [list_providers] OAuthLogin: client_id: %s', provider['client_id'])
            _logger.debug('🔹 [list_providers] OAuthLogin: rredirect_uri: %s', return_url)
            _logger.debug('🔹 [list_providers] OAuthLogin: scope: %s', provider['scope'])
            _logger.debug('🔹 [list_providers] OAuthLogin: state: %s', json.dumps(state))
            _logger.debug('🔹 [list_providers] OAuthLogin: is_openid: %s', provider['is_openid'])
            _logger.debug('🔹 [list_providers] OAuthLogin: client_secret: %s', client_secret)

        return providers  # This return should be outside the loop

    @http.route()
    def web_login(self, *args, **kw):
        ensure_db()

        _logger.info("🔹 [web_login] OAuthLogin:  HTTP Method: %s", request.httprequest.method)
        _logger.info("🔹 [web_login] OAuthLogin:  Session User ID: %s", request.session.uid)
        _logger.info("🔹 [web_login] OAuthLogin:  Redirect Parameter: %s", request.params.get('redirect'))
        _logger.info("🔹 [web_login] OAuthLogin:  OAuth Error Parameter: %s", request.params.get('oauth_error'))

        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            # Redirect if already logged in and redirect param is present
             _logger.info("🔹 [web_login] OAuthLogin:  ✅ User already logged in. Redirecting to: %s", request.params.get('redirect'))
             return request.redirect(request.params.get('redirect'))

        providers = self.list_providers()
        _logger.info("🔹 [web_login] OAuthLogin:   Available Providers: %s", [p['name'] for p in providers])

        # Recursive call to parent web_login
        response = super(OAuthLogin, self).web_login(*args, **kw)
        _logger.info("🔹 [web_login] OAuthLogin:   Response Type: %s", type(response))

       # Check if response is a QWeb template (login form)
        if response.is_qweb:
             error = request.params.get('oauth_error')
             if error == '1':
                 error = _("Sign up is not allowed on this database.")
             elif error == '2':
                 error = _("Access Denied")
             elif error == '3':
                 error = _("You do not have access to this database or your invitation has expired. Please ask for an invitation and be sure to follow the link in your invitation email.")
             else:
                 error = None

             response.qcontext['providers'] = providers
             if error:
                _logger.warning("⚠️ [web_login] OAuthLogin:   OAuth Error: %s", error)
                response.qcontext['error'] = error

        return response

    def get_auth_signup_qcontext(self):
        result = super(OAuthLogin, self).get_auth_signup_qcontext()
        result["providers"] = self.list_providers()
        return result

class OAuthController(oauth_controller):

    @http.route('/auth_oauth/signin', type='http', auth='none', csrf=False)
    def signin(self, **kw):
        """OAuth2 callback handler for authentication"""
        if "state" not in kw:
            _logger.error("🔹 [signin] OAuthController: Missing state parameter")
            return request.redirect("/web/login?oauth_error=2", 303)

        state = json.loads(kw["state"])
        dbname = state.get("d")
        _logger.debug("🔹 [signin] OAuthController: dbname: %s", state.get("d") )
        _logger.debug("🔹 [signin] OAuthController: http.dbname: %s", http.db_filter([dbname]) )

        if not dbname or not http.db_filter([dbname]):
            return BadRequest()

        request.session.db = dbname
        ensure_db(db=dbname)

        provider_id = state.get("p")
        provider = request.env["auth.oauth.provider"].sudo().browse(provider_id)

        _logger.debug("🔹 [signin] OAuthController: privider_id: %s", provider_id )
        _logger.debug("🔹 [signin] OAuthController: provider: %s", provider )

        if not provider.exists():
            _logger.error(f"🔹 [signin]  OAuthController: Provider with ID {provider_id} not found")
            return request.redirect("/web/login?oauth_error=2", 303)

        request.update_context(**clean_context(state.get("c", {})))

        # Check OAuth flow type
        flow_type = provider.flow_type

        _logger.debug("🔹 [signin] OAuthController: flow_type: %s", provider.flow_type )
        _logger.debug("🔹 [signin] OAuthController: kw: %s", kw )

        # Handle Authorization Code Flow (exchange code for token)
        if "code" in kw and flow_type == "authorization_code":
            token_data = self.exchange_code_for_token(kw["code"], provider)
            access_token = token_data.get("access_token")
            id_token = token_data.get("id_token")


        # Handle Implicit & Hybrid Flows (id_token is returned directly)
        else:
            access_token = kw.get("access_token")
            id_token = kw.get("id_token")

        _logger.debug("🔹 [signin] OAuthController: access_token: %s", access_token )
        _logger.debug("🔹 [signin] OAuthController: token_data: %s", token_data)
        _logger.debug("🔹 [signin] OAuthController: id_token : %s", id_token  )

        if not access_token:
           _logger.error("🔹 [signin] OAuthController:  Missing access_token in response")
           return request.redirect("/web/login?oauth_error=2", 303)

        if not id_token:
            _logger.error("🔹 [signin] OAuthController: Missing id_token in response")
            return request.redirect("/web/login?oauth_error=2", 303)


        _logger.debug("🔹 [signin] OAuthController: Available methods in res.users: %s", dir(request.env["res.users"]))
        _logger.debug("🔹 [signin] OAuthController: Does 'auth_oauth' exist? %s", hasattr(request.env["res.users"], 'auth_oauth'))
        try:
            # Authenticate user
            _logger.debug("🔹 [signin] OAuthController:  Authenticate user, try block _, loign, key")
            _, login, key = request.env["res.users"].with_user(SUPERUSER_ID).auth_oauth(provider.id, {"access_token": access_token})

            _logger.debug("🔹 [signin] OAuthController:  Authenticate user, try block request.env.cr.commit()")
            request.env.cr.commit()

            # Determine where to redirect user after login
            _logger.debug("🔹 [signin] OAuthController:  Authenticate user, try block: Determine where to redirect user after login")
            action = state.get("a")
            menu = state.get("m")
            redirect = werkzeug.urls.url_unquote_plus(state.get("r")) if state.get("r") else False
            url = "/web"

            if redirect:
                url = redirect
            elif action:
                url = f"/web/action-{action}"
            elif menu:
                url = f"/web?menu_id={menu}"

            # Authenticate session in Odoo
            _logger.debug("🔹 [signin] OAuthController:  Authenticate user, try block: Authenticate session in Odoo")
            credential = {"login": login, "token": key, "type": "oauth_token"}
            auth_info = request.session.authenticate(dbname, credential)
            resp = request.redirect(_get_login_redirect_url(auth_info["uid"], url), 303)
            resp.autocorrect_location_header = False

            _logger.error("🔹 [signin] OAuthController: Authenticate session in Odoo")
            _logger.error("🔹 [signin] OAuthController: login: %s", login)
            _logger.error("🔹 [signin] OAuthController: token: %s", key)
            _logger.error("🔹 [signin] OAuthController: auth_info: %s", auth_info)

            # Ensure user has access to /web
            if werkzeug.urls.url_parse(resp.location).path == "/web" and not request.env.user._is_internal():
                resp.location = "/"

            return resp

        except AttributeError:
            _logger.error(f"🔹 [signin] OAuthController: auth_signup not installed on database {dbname}: OAuth sign-up cancelled.")
            return request.redirect("/web/login?oauth_error=1", 303)

        except AccessDenied:
            _logger.info("🔹 [signin]  OAuthController: Access denied")
            return request.redirect("/web/login?oauth_error=3", 303)

        except Exception:
            _logger.exception("🔹 [signin]  OAuthController: Unexpected error")
            return request.redirect("/web/login?oauth_error=2", 303)

    def exchange_code_for_token(self, code, provider):
        """Exchange authorization code for token"""
        import requests

        token_url = provider.data_endpoint
        client_id = provider.client_id
        client_secret = provider.client_secret

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": request.httprequest.url_root + "auth_oauth/signin",
            "client_id": client_id,
            "client_secret": client_secret,
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(token_url, data=data, headers=headers)

        if response.status_code == 200:
           token_data = response.json()
           _logger.debug("🔹 [exchange_code_for_token]  OAuthController: Token exchange successful: %s", token_data)
           return token_data
        else:
           _logger.error("🔹 [exchange_code_for_token]  OAuthController: Failed to exchange code for token: %s", response.text)
           raise AccessDenied("OAuth token exchange failed")

