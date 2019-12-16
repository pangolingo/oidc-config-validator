#!/usr/bin/env python3

import sys
import requests
from urllib.parse import urlparse
import validators


# HELPERS

def is_url(url):
  try:
    result = urlparse(url)
    return all([result.scheme, result.netloc])
  except ValueError:
    return False

def warn(warning):
  print("WARNING: " + warning)


def assert_key_is_array(dict, key_name):
  assert isinstance(dict[key_name], list), f"`{key_name}` is not an array"


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

assert 'issuer' in json, "`issuer` key missing"
assert validators.url(json['issuer']), "`issuer` is not a valid URL"
# todo: must be https scheme, must have no query or fragment component

assert 'authorization_endpoint' in json, "`authorization_endpoint` key missing"
assert validators.url(json['authorization_endpoint']), "`authorization_endpoint` is not a valid URL"


assert 'token_endpoint' in json, "`token_endpoint` key missing"
assert validators.url(json['token_endpoint']), "`token_endpoint` is not a valid URL"
# todo: required unless only implicit flow is used

if 'userinfo_endpoint' not in json:
  warn('`userinfo_endpoint` is missing - this endpoint is recommended')
else :
  assert validators.url(json['userinfo_endpoint']), "`userinfo_endpoint` is not a valid URL"
# todo: must be https

assert 'jwks_uri' in json, "`jwks_uri` key missing"
assert validators.url(json['jwks_uri']), "`jwks_uri` is not a valid URL"

if 'registration_endpoint' not in json:
  warn('`registration_endpoint` is missing - this endpoint is recommended')
else :
  assert validators.url(json['registration_endpoint']), "`registration_endpoint` is not a valid URL"


if 'scopes_supported' not in json:
  warn('`scopes_supported` is missing - this key is recommended')
else :
  assert isinstance(json['scopes_supported'], list), "`scopes_supported` is not an array"
  assert len(json['scopes_supported']) > 0, "`scopes_supported` array is empty"
  assert 'openid' in json['scopes_supported'], "`scopes_supported` array is missing the `openid` scope"
# todo: warn if scopes list contains nonstandard scopes: https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1


assert 'response_types_supported' in json, "`response_types_supported` key missing"
assert isinstance(json['response_types_supported'], list), "`response_types_supported` is not an array"
assert len(json['response_types_supported']) > 0, "`response_types_supported` array is empty"
# todo: require these to all be valid OAuth 2.0 response_types
if IS_DYNAMIC:
  assert 'code' in json['response_types_supported'], "`code` value is missing the `response_types_supported` array"
  assert 'id_token' in json['response_types_supported'], "`id_token` value is missing the `response_types_supported` array"
  assert 'token' in json['response_types_supported'], "`token` value is missing the `response_types_supported` array"


if 'response_modes_supported' in json:
  assert isinstance(json['response_modes_supported'], list), "`response_modes_supported` is not an array"
  if len(json['response_types_supported']) <= 0:
    warn( "`response_types_supported` array is present but empty")
# todo: require these all to be valid response_mode values

# THIS IS BROKEN FOR VERIZON - TEMPORARILY DISABLE
if 'grant_types_supported' in json:
  assert isinstance(json['grant_types_supported'], list), "`grant_types_supported` is not an array"
  if len(json['grant_types_supported']) <= 0:
    warn( "`grant_types_supported` array is present but empty")
  if IS_DYNAMIC:
    assert 'authorization_code' in json['grant_types_supported'], "`authorization_code` value is missing the `grant_types_supported` array"
    assert 'implicit' in json['grant_types_supported'], "`implicit` value is missing the `grant_types_supported` array"
# todo: require these all to be valid grant type values


if 'acr_values_supported' in json:
  assert isinstance(json['acr_values_supported'], list), "`acr_values_supported` is not an array"
  if len(json['acr_values_supported']) <= 0:
    warn( "`acr_values_supported` array is present but empty")


assert 'subject_types_supported' in json, "`subject_types_supported` key missing"
assert isinstance(json['subject_types_supported'], list), "`subject_types_supported` is not an array"
assert len(json['subject_types_supported']) > 0, "`subject_types_supported` array is empty"
assert ('pairwise' in json['subject_types_supported'] or 'public' in json['subject_types_supported']), "`subject_types_supported` must include only `pairwise` and `public` values"



assert 'id_token_signing_alg_values_supported' in json, "`id_token_signing_alg_values_supported` key missing"
assert isinstance(json['id_token_signing_alg_values_supported'], list), "`id_token_signing_alg_values_supported` is not an array"
assert 'RS256' in json['id_token_signing_alg_values_supported'], "`id_token_signing_alg_values_supported` must include `RS256`"
# TODO: only allow valid JWS signing algorithms + 'none'


if 'id_token_encryption_alg_values_supported' in json:
  assert isinstance(json['id_token_encryption_alg_values_supported'], list), "`id_token_encryption_alg_values_supported` is not an array"
  if len(json['id_token_encryption_alg_values_supported']) <= 0:
    warn( "`id_token_encryption_alg_values_supported` array is present but empty")
# TODO: only allow valid JWE encryption algorithms


if 'id_token_encryption_enc_values_supported' in json:
  assert isinstance(json['id_token_encryption_enc_values_supported'], list), "`id_token_encryption_enc_values_supported` is not an array"
  if len(json['id_token_encryption_enc_values_supported']) <= 0:
    warn( "`id_token_encryption_enc_values_supported` array is present but empty")
# TODO: only allow valid JWE encryption algorithms



if 'userinfo_signing_alg_values_supported' in json:
  assert isinstance(json['userinfo_signing_alg_values_supported'], list), "`userinfo_signing_alg_values_supported` is not an array"
  if len(json['userinfo_signing_alg_values_supported']) <= 0:
    warn( "`userinfo_signing_alg_values_supported` array is present but empty")
# TODO: only allow valid JWS signing algorithms + none


if 'userinfo_encryption_alg_values_supported' in json:
  assert isinstance(json['userinfo_encryption_alg_values_supported'], list), "`userinfo_encryption_alg_values_supported` is not an array"
  if len(json['userinfo_encryption_alg_values_supported']) <= 0:
    warn( "`userinfo_encryption_alg_values_supported` array is present but empty")
# TODO: only allow valid JWE encryption algorithms


if 'userinfo_encryption_enc_values_supported' in json:
  assert isinstance(json['userinfo_encryption_enc_values_supported'], list), "`userinfo_encryption_enc_values_supported` is not an array"
  if len(json['userinfo_encryption_enc_values_supported']) <= 0:
    warn( "`userinfo_encryption_enc_values_supported` array is present but empty")
# TODO: only allow valid JWE encryption algorithms



if 'request_object_signing_alg_values_supported' in json:
  assert isinstance(json['request_object_signing_alg_values_supported'], list), "`request_object_signing_alg_values_supported` is not an array"
  if len(json['request_object_signing_alg_values_supported']) <= 0:
    warn( "`request_object_signing_alg_values_supported` array is present but empty")
  if 'none' not in json['request_object_signing_alg_values_supported']:
    warn( "`request_object_signing_alg_values_supported` array should include `none`")
  if 'RS256' not in json['request_object_signing_alg_values_supported']:
    warn( "`request_object_signing_alg_values_supported` array should include `RS256`")
# TODO: only allow valid JWS signing algorithms


if 'request_object_encryption_alg_values_supported' in json:
  assert isinstance(json['request_object_encryption_alg_values_supported'], list), "`request_object_encryption_alg_values_supported` is not an array"
  if len(json['request_object_encryption_alg_values_supported']) <= 0:
    warn( "`request_object_encryption_alg_values_supported` array is present but empty")
# TODO: only allow valid JWE encryption algorithms


if 'request_object_encryption_enc_values_supported' in json:
  assert isinstance(json['request_object_encryption_enc_values_supported'], list), "`request_object_encryption_enc_values_supported` is not an array"
  if len(json['request_object_encryption_enc_values_supported']) <= 0:
    warn( "`request_object_encryption_enc_values_supported` array is present but empty")
# TODO: only allow valid JWE encryption algorithms



if 'token_endpoint_auth_methods_supported' in json:
  assert isinstance(json['token_endpoint_auth_methods_supported'], list), "`token_endpoint_auth_methods_supported` is not an array"
  if len(json['token_endpoint_auth_methods_supported']) <= 0:
    warn( "`token_endpoint_auth_methods_supported` array is present but empty")
# TODO: warn if others are used besides standard options: client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt


if 'token_endpoint_auth_signing_alg_values_supported' in json:
  assert isinstance(json['token_endpoint_auth_signing_alg_values_supported'], list), "`token_endpoint_auth_signing_alg_values_supported` is not an array"
  if len(json['token_endpoint_auth_signing_alg_values_supported']) <= 0:
    warn( "`token_endpoint_auth_signing_alg_values_supported` array is present but empty")
  assert 'none' not in json['token_endpoint_auth_signing_alg_values_supported'], "`token_endpoint_auth_signing_alg_values_supported` does not allow value `none`"
  if 'RS256' not in json['token_endpoint_auth_signing_alg_values_supported']:
    warn( "`token_endpoint_auth_signing_alg_values_supported` array should include `RS256`")
# TODO: only allow valid JWS signing algorithms


if 'display_values_supported' in json:
  assert isinstance(json['display_values_supported'], list), "`display_values_supported` is not an array"
  if len(json['display_values_supported']) <= 0:
    warn( "`display_values_supported` array is present but empty")
# TODO: only allow valid display parameter values from OIDC Core 1.0


if 'claim_types_supported' in json:
  assert isinstance(json['claim_types_supported'], list), "`claim_types_supported` is not an array"
  if len(json['claim_types_supported']) <= 0:
    warn( "`claim_types_supported` array is present but empty")
# TODO: only allow valid claim type values from OIDC Core 1.0: normal, aggregated, and distributed


if 'claims_supported' in json:
  assert isinstance(json['claims_supported'], list), "`claims_supported` is not an array"
  if len(json['claims_supported']) <= 0:
    warn( "`claims_supported` array is present but empty")
else:
  warn( "`claims_supported` key is missing, but recommended")



if 'service_documentation' in json:
  assert validators.url(json['service_documentation']), "`service_documentation` is not a valid URL"


if 'claims_locales_supported' in json:
  assert isinstance(json['claims_locales_supported'], list), "`claims_locales_supported` is not an array"
  if len(json['claims_locales_supported']) <= 0:
    warn( "`claims_locales_supported` array is present but empty")
# TODO: validate all the language tag values against RFC5646


if 'ui_locales_supported' in json:
  assert isinstance(json['ui_locales_supported'], list), "`ui_locales_supported` is not an array"
  if len(json['ui_locales_supported']) <= 0:
    warn( "`ui_locales_supported` array is present but empty")

if 'claims_parameter_supported' in json:
  assert isinstance(json['claims_parameter_supported'], bool), "`claims_parameter_supported` is not an boolean"

if 'request_parameter_supported' in json:
  assert isinstance(json['request_parameter_supported'], bool), "`request_parameter_supported` is not an boolean"

if 'request_uri_parameter_supported' in json:
  assert isinstance(json['request_uri_parameter_supported'], bool), "`request_uri_parameter_supported` is not an boolean"


if 'require_request_uri_registration' in json:
  assert isinstance(json['require_request_uri_registration'], bool), "`require_request_uri_registration` is not an boolean"


if 'op_policy_uri' in json:
  assert validators.url(json['op_policy_uri']), "`op_policy_uri` is not a valid URL"

if 'op_tos_uri' in json:
  assert validators.url(json['op_tos_uri']), "`op_tos_uri` is not a valid URL"

print('The OIDC config is good')