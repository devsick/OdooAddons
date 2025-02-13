from odoo import fields, models


class AuthOAuthProvider(models.Model):

    _inherit = 'auth.oauth.provider'

    client_secret = fields.Char(string='Client Secret')
    flow_type = fields.Selection([
        ("implicit", "Implicit Flow (id_token token)"),
        ("authorization_code", "Authorization Code Flow"),
        ("hybrid", "Hybrid Flow (code id_token)")
    ], string="OAuth Flow Type", default="implicit", required=True)
    is_openid = fields.Boolean(string="Use OpenID Connect", default=False)
    provider_type = fields.Selection([
        ('generic', 'Generic OIDC/OAuth2'),
        ('nextcloud', 'Nextcloud'),
        ('keycloak', 'Keycloak'),
        ('google', 'Google'),
        ('okta', 'Okta'),
    ], string="Provider Type", default='generic', required=True)
