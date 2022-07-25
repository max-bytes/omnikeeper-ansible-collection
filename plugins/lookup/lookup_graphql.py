# TODO
"""
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# TODO
DOCUMENTATION = """
"""

# TODO
RETURN = """
"""

import os
import traceback
import urllib.request, json
from ansible.module_utils.six import raise_from
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleLookupError, AnsibleError
from ansible.utils.display import Display
from ansible.module_utils.common.text.converters import to_native

try:
  from oauthlib.oauth2 import LegacyApplicationClient
  from requests_oauthlib import OAuth2Session
except ImportError as imp_exc:
  OAUTHLIB_IMPORT_ERROR = imp_exc
else:
  OAUTHLIB_IMPORT_ERROR = None

try:
  from gql import gql, Client
  from gql.transport.aiohttp import AIOHTTPTransport
except ImportError as imp_exc:
  GQL_IMPORT_ERROR = imp_exc
else:
  GQL_IMPORT_ERROR = None

display = Display()

class LookupModule(LookupBase):

  def __init__(self, *args, **kwargs) -> None:
    super(LookupModule, self).__init__(*args, **kwargs)

    if OAUTHLIB_IMPORT_ERROR:
      raise_from(
          AnsibleError('oauthlib and requests-oauthlib must be installed to use this plugin'),
          OAUTHLIB_IMPORT_ERROR)
    if GQL_IMPORT_ERROR:
      raise_from(
          AnsibleError('gql (including aiohttp) must be installed to use this plugin'),
          OAUTHLIB_IMPORT_ERROR)

  def run(self, query, query_variables=None, **kwargs):

    single_query = query[0]

    omnikeeper_url = kwargs.get("url")
    if query_variables is not None and not isinstance(query_variables, dict):
      raise AnsibleLookupError("Parameter \"query_variables\" must be dictionary")
    Display().v("Variables: %s" % query_variables)

    if omnikeeper_url is None:
      raise AnsibleLookupError("Missing parameters \"url\"")

    username = kwargs.get("username")
    password = kwargs.get("password")
    token = kwargs.get("token")
    oauth_insecure_transport = kwargs.get("oauth_insecure_transport")

    if oauth_insecure_transport:
      os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    client_id = kwargs.get("client_id") or "omnikeeper"

    try:
      if token is None:

        if username is None:
          raise AnsibleLookupError("Missing parameters \"username\", when parameter \"token\" is not set either")
        if password is None:
          raise AnsibleLookupError("Missing parameters \"password\", when parameter \"token\" is not set either")

        Display().v("Using provided username (\" %s \") and password" % username)

        # first retrieve token_url from omnikeeper endpoint
        oauth_url = "%s/.well-known/openid-configuration" % omnikeeper_url
        with urllib.request.urlopen(oauth_url) as url:
          data = json.loads(url.read().decode())
        token_url = data["token_endpoint"]

        # now fetch access_token from token_url, providing username and password
        client = LegacyApplicationClient(client_id=client_id)
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=token_url, username=username, password=password)
        access_token = token["access_token"]
      else:
        Display().v("Using provided access token")
        access_token = token

      # perform query
      graphql_url = "%s/graphql" % omnikeeper_url
      transport = AIOHTTPTransport(url=graphql_url, headers={'Authorization': "Bearer %s" % access_token})
      client = Client(transport=transport, fetch_schema_from_transport=True)
      prepared_query = gql(single_query)
      result = client.execute(prepared_query, variable_values=query_variables)
      return result

    except Exception as e:
      Display().v(traceback.format_exc())
      raise AnsibleError('Error occured, original exception: %s' % to_native(e))