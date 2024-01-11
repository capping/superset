import json
import logging
import requests

from flask import redirect
from flask_appbuilder.views import expose
from flask_appbuilder.security.views import AuthOAuthView
from superset.security import SupersetSecurityManager


class CustomAuthOAuthView(AuthOAuthView):
    @expose("/logout/")
    def logout(self, provider="geely", register=None):
        provider_obj = self.appbuilder.sm.oauth_remotes[provider]
        logging.info(
            "logout_url: {0}".format(provider_obj.server_metadata['logout_url']))
        super().logout()
        return redirect(provider_obj.server_metadata['logout_url'])


class CustomOauth2SecurityManager(SupersetSecurityManager):
    # override the logout function
    authoauthview = CustomAuthOAuthView

    def oauth_user_info(self, provider, response=None):
        logging.debug("Oauth2 provider: {0}.".format(provider))
        logging.debug("oauth_tokengetter: {0}.".format(self.oauth_tokengetter()))
        if provider == 'geely':
            # As example, this line request a GET to base_url + '/' + userDetails
            # with Bearer  Authentication, and expects that authorization server
            # checks the token, and response with user details
            url = 'http://passport-test.test.geely.com/api/bff/v1.2/oauth2/userinfo?access_token={0}'.format(
                self.oauth_tokengetter()[0])
            response = requests.get(url).text
            data = json.loads(response)
            me = data['data']
            logging.debug("user_data: {0}".format(me))
            return {'name': me['email'], 'email': me['email'], 'id': me['ou_id'],
                    'username': me['nickname'], 'first_name': '', 'last_name': ''}
