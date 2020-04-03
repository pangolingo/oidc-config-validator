#!/usr/bin/env python3

import sys
import requests
from urllib.parse import urlparse
import validators


errors = []

# HELPERS

# assert without throwing error
def m_assert(test, message):
  m = f"ERROR: {message}"
  if not test:
    print(m)
    errors.append(m)

# assert and throw assertion error
def e_assert(test, message):
  assert test, message

def is_url(url):
  try:
    result = urlparse(url)
    return all([result.scheme, result.netloc])
  except ValueError:
    return False

def warn(warning):
  print("WARNING: " + warning)

def recommend(recommendation):
  print("RECOMMENDATION: " + recommendation)


def assert_key_in_dict(dict, key_name):
  m_assert(key_name in dict, f"`{key_name}` key missing")

def assert_key_is_array(dict, key_name):
  m_assert(isinstance(dict[key_name], list), f"`{key_name}` is not an array")

def assert_key_is_boolean(dict, key_name):
  m_assert(isinstance(dict[key_name], bool), f"`{key_name}` is not an boolean")

def assert_key_is_url(dict, key_name):
  is_string = isinstance(dict[key_name], str)
  m_assert(is_string, f"`{key_name}` is not a string")
  if is_string:
    m_assert(validators.url(dict[key_name]), f"`{key_name}` is not a valid URL")

def assert_key_is_not_empty_array(dict, key_name):
  m_assert(len(dict[key_name]) > 0, f"`{key_name}` array is empty")

def warn_if_key_is_empty_array(dict, key_name):
  if len(dict[key_name]) < 1:
    warn( f"`{key_name}` array is present but empty")

# BEGIN:
IS_DYNAMIC = False



path = sys.argv[-1]

if not path or not is_url(path):
  raise ValueError('Include a valid OIDC path as the first command line argument')

r = requests.get(path)

# throw an HTTPError error if we received an error status code
r.raise_for_status()

# will throw a ValueERror if the JSON couldn't be decoded
json = r.json()

# do checks

assert_key_in_dict(json, 'issuer')
assert_key_is_url(json, 'issuer')
# todo: must be https scheme, must have no query or fragment component
print(f"Testing config for issuer \"{json['issuer']}\"")

assert_key_in_dict(json, 'authorization_endpoint')
assert_key_is_url(json, 'authorization_endpoint')


assert_key_in_dict(json, 'token_endpoint')
assert_key_is_url(json, 'token_endpoint')
# todo: required unless only implicit flow is used

if 'userinfo_endpoint' not in json:
  recommend('`userinfo_endpoint` is missing - this endpoint is recommended')
else :
  assert_key_is_url(json, 'userinfo_endpoint')
# todo: must be https

assert_key_in_dict(json, 'jwks_uri')
assert_key_is_url(json, 'jwks_uri')

if 'registration_endpoint' not in json:
  recommend('`registration_endpoint` is missing - this endpoint is recommended')
else:
  assert_key_is_url(json, 'registration_endpoint')


if 'scopes_supported' not in json:
  recommend('`scopes_supported` is missing - this key is recommended')
else :
  assert_key_is_array(json, 'scopes_supported')
  assert_key_is_not_empty_array(json, 'scopes_supported')
  m_assert('openid' in json['scopes_supported'], "`scopes_supported` array is missing the `openid` scope")
# todo: warn if scopes list contains nonstandard scopes: https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1


assert_key_in_dict(json, 'response_types_supported')
assert_key_is_array(json, 'response_types_supported')
assert_key_is_not_empty_array(json, 'response_types_supported')
# todo: require these to all be valid OAuth 2.0 response_types
if IS_DYNAMIC:
  m_assert('code' in json['response_types_supported'], "`code` value is missing the `response_types_supported` array")
  m_assert('id_token' in json['response_types_supported'], "`id_token` value is missing the `response_types_supported` array")
  m_assert('token' in json['response_types_supported'], "`token` value is missing the `response_types_supported` array")


if 'response_modes_supported' in json:
  assert_key_is_array(json, 'response_modes_supported')
  warn_if_key_is_empty_array(json, 'response_types_supported')
# todo: require these all to be valid response_mode values

# THIS IS BROKEN FOR VERIZON - TEMPORARILY DISABLE
if 'grant_types_supported' in json:
  assert_key_is_array(json, 'grant_types_supported')
  warn_if_key_is_empty_array(json, 'grant_types_supported')
  if IS_DYNAMIC:
    m_assert('authorization_code' in json['grant_types_supported'], "`authorization_code` value is missing the `grant_types_supported` array")
    m_assert('implicit' in json['grant_types_supported'], "`implicit` value is missing the `grant_types_supported` array")
# todo: require these all to be valid grant type values


if 'acr_values_supported' in json:
  assert_key_is_array(json, 'acr_values_supported')
  warn_if_key_is_empty_array(json, 'acr_values_supported')


assert_key_is_array(json, 'subject_types_supported')
assert_key_is_not_empty_array(json, 'subject_types_supported')
m_assert(('pairwise' in json['subject_types_supported'] or 'public' in json['subject_types_supported']), "`subject_types_supported` must include only `pairwise` and `public` values")



m_assert('id_token_signing_alg_values_supported' in json, "`id_token_signing_alg_values_supported` key missing")
assert_key_is_array(json, 'id_token_signing_alg_values_supported')
m_assert('RS256' in json['id_token_signing_alg_values_supported'], "`id_token_signing_alg_values_supported` must include `RS256`")
# TODO: only allow valid JWS signing algorithms + 'none'


if 'id_token_encryption_alg_values_supported' in json:
  assert_key_is_array(json, 'id_token_encryption_alg_values_supported')
  warn_if_key_is_empty_array(json, 'id_token_encryption_alg_values_supported')
# TODO: only allow valid JWE encryption algorithms


if 'id_token_encryption_enc_values_supported' in json:
  assert_key_is_array(json, 'id_token_encryption_enc_values_supported')
  warn_if_key_is_empty_array(json, 'id_token_encryption_enc_values_supported')
# TODO: only allow valid JWE encryption algorithms



if 'userinfo_signing_alg_values_supported' in json:
  assert_key_is_array(json, 'userinfo_signing_alg_values_supported')
  warn_if_key_is_empty_array(json, 'userinfo_signing_alg_values_supported')
# TODO: only allow valid JWS signing algorithms + none


if 'userinfo_encryption_alg_values_supported' in json:
  assert_key_is_array(json, 'userinfo_encryption_alg_values_supported')
  warn_if_key_is_empty_array(json, 'userinfo_encryption_alg_values_supported')
# TODO: only allow valid JWE encryption algorithms


if 'userinfo_encryption_enc_values_supported' in json:
  assert_key_is_array(json, 'userinfo_encryption_enc_values_supported')
  warn_if_key_is_empty_array(json, 'userinfo_encryption_enc_values_supported')
# TODO: only allow valid JWE encryption algorithms



if 'request_object_signing_alg_values_supported' in json:
  assert_key_is_array(json, 'request_object_signing_alg_values_supported')
  warn_if_key_is_empty_array(json, 'request_object_signing_alg_values_supported')
  if 'none' not in json['request_object_signing_alg_values_supported']:
    recommend( "`request_object_signing_alg_values_supported` array should include `none`")
  if 'RS256' not in json['request_object_signing_alg_values_supported']:
    recommend( "`request_object_signing_alg_values_supported` array should include `RS256`")
# TODO: only allow valid JWS signing algorithms


if 'request_object_encryption_alg_values_supported' in json:
  assert_key_is_array(json, 'request_object_encryption_alg_values_supported')
  warn_if_key_is_empty_array(json, 'request_object_encryption_alg_values_supported')
# TODO: only allow valid JWE encryption algorithms


if 'request_object_encryption_enc_values_supported' in json:
  assert_key_is_array(json, 'request_object_encryption_enc_values_supported')
  warn_if_key_is_empty_array(json, 'request_object_encryption_enc_values_supported')
# TODO: only allow valid JWE encryption algorithms



if 'token_endpoint_auth_methods_supported' in json:
  assert_key_is_array(json, 'token_endpoint_auth_methods_supported')
  warn_if_key_is_empty_array(json, 'token_endpoint_auth_methods_supported')
# TODO: warn if others are used besides standard options: client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt


if 'token_endpoint_auth_signing_alg_values_supported' in json:
  assert_key_is_array(json, 'token_endpoint_auth_signing_alg_values_supported')
  warn_if_key_is_empty_array(json, 'token_endpoint_auth_signing_alg_values_supported')
  m_assert('none' not in json['token_endpoint_auth_signing_alg_values_supported'], "`token_endpoint_auth_signing_alg_values_supported` does not allow value `none`")
  if 'RS256' not in json['token_endpoint_auth_signing_alg_values_supported']:
    recommend( "`token_endpoint_auth_signing_alg_values_supported` array should include `RS256`")
# TODO: only allow valid JWS signing algorithms


if 'display_values_supported' in json:
  assert_key_is_array(json, 'display_values_supported')
  warn_if_key_is_empty_array(json, 'display_values_supported')
# TODO: only allow valid display parameter values from OIDC Core 1.0


if 'claim_types_supported' in json:
  assert_key_is_array(json, 'claim_types_supported')
  warn_if_key_is_empty_array(json, 'claim_types_supported')
# TODO: only allow valid claim type values from OIDC Core 1.0: normal, aggregated, and distributed


if 'claims_supported' in json:
  assert_key_is_array(json, 'claims_supported')
  warn_if_key_is_empty_array(json, 'claims_supported')
else:
  recommend( "`claims_supported` key is missing, but recommended")



if 'service_documentation' in json:
  assert_key_is_url(json, 'service_documentation')


if 'claims_locales_supported' in json:
  assert_key_is_array(json, 'claims_locales_supported')
  warn_if_key_is_empty_array(json, 'claims_locales_supported')
# TODO: validate all the language tag values against RFC5646


if 'ui_locales_supported' in json:
  assert_key_is_array(json, 'ui_locales_supported')
  warn_if_key_is_empty_array(json, 'ui_locales_supported')

if 'claims_parameter_supported' in json:
  assert_key_is_boolean(json, 'claims_parameter_supported')

if 'request_parameter_supported' in json:
  assert_key_is_boolean(json, 'request_parameter_supported')

if 'request_uri_parameter_supported' in json:
  assert_key_is_boolean(json, 'request_uri_parameter_supported')


if 'require_request_uri_registration' in json:
  assert_key_is_boolean(json, 'require_request_uri_registration')


if 'op_policy_uri' in json:
  assert_key_is_url(json, 'op_policy_uri')

if 'op_tos_uri' in json:
  assert_key_is_url(json, 'op_tos_uri')

if len(errors) < 1:
  print('The OIDC config is good')
else:
  print(f"{len(errors)} errors in the OIDC config")