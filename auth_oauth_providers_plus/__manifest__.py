{
    'name': "Oauth2 Oauth providers plus",

    'summary': """
      Increase the auth_oauth module to make oauth signin for different providers, openidConnect, special Nextcloud as oauth provider.
""",

    'description': """
Key Features
============

- This module adds some new fields to the auth_oauth model and view, makes completely oauth2 signin possible for local Nextcloud, Keycloak, Okta. Can use OAuth2 or openidConnect.

Editions Supported
==================
1. Community Edition
2. Enterprise Edition

    """,

    'author': "Anja Simons",
    'website': "https://anjasimons.odoo.com",
    'support': "anja.simons@outlook.de",
    'category': 'Extra Tools',
    'version': '0.1',

    # any module necessary for this one to work correctly
    'depends': ['auth_oauth'],

    # always loaded
    'data': [
        'views/auth_oauth_views.xml',
    ],

    'images': ['static/description/Odoo_Provider.png'],
    'installable': True,
    'application': False,
    'auto_install': True,
    'price': 0.0,
    'currency': 'EUR',
    'license': 'OPL-1',
}
