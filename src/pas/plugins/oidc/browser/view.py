from oic.oic.message import EndSessionRequest
from oic.oic.message import IdToken
from pas.plugins.oidc import _
from pas.plugins.oidc import logger
from pas.plugins.oidc import utils
from pas.plugins.oidc.plugins import OAuth2ConnectionException
from pas.plugins.oidc.session import Session
from plone import api
from Products.Five.browser import BrowserView
from urllib.parse import quote
from zExceptions import Unauthorized
from datetime import datetime
from datetime import timedelta
from zExceptions import NotFound
import requests
import json
from oic import rndstr
import uuid
import hashlib
import base64
import random
import os
import re
from copy import deepcopy
from urllib.parse import urlencode
from ..utils import get_jwk_from_jwt
from ..utils import key_from_jwk_dict
from ..utils import unpad_jwt_payload
from ..utils import verify_at_hash
from ..utils import unpad_jwt_head
from ..utils import decrypt_jwe



class InvalidTrustchain(Exception):
    pass


ENTITY_STATUS = {
    "unreachable": False,
    "valid": True,
    "signature_failed": False,
    "not_valid": False,
    "unknown": None,
    "expired": None,
}

# required for onboarding checks and also for all the leafs
OIDCFED_DEFAULT_TRUST_ANCHOR = "http://trust-anchor.org:8000"


# TODO: move to settings
OIDCFED_IDENTITY_PROVIDERS = {
  "spid": {
    "http://127.0.0.1:8000/oidc/op" : OIDCFED_DEFAULT_TRUST_ANCHOR,
  },
  "cie": {
    "http://cie-provider.org:8002/oidc/op" : OIDCFED_DEFAULT_TRUST_ANCHOR,
  }
}

FEDERATION_DEFAULT_EXP = 2880

def get_http_url(urls: list, httpc_params: dict = {}) -> list:
    responses = []
    for i in urls:
        res = requests.get(i, **httpc_params) # nosec - B113
        responses.append(res.content.decode())
    return responses


def get_jwks(metadata: dict, federation_jwks:list = []) -> dict:
    """
    get jwks or jwks_uri or signed_jwks_uri
    """
    jwks_list = []
    if metadata.get('jwks'):
        jwks_list = metadata["jwks"]["keys"]
    elif metadata.get('jwks_uri'):
        try:
            jwks_uri = metadata["jwks_uri"]
            jwks_list = get_http_url(
                [jwks_uri], httpc_params={"verify": True, "timeout": 4},
            )
            jwks_list = json.loads(jwks_list[0])
        except Exception as e:
            logger.error(f"Failed to download jwks from {jwks_uri}: {e}")
    elif metadata.get('signed_jwks_uri'):
        try:
            signed_jwks_uri = metadata["signed_jwks_uri"]
            jwks_list = get_http_url(
                [signed_jwks_uri], httpc_params={"verify": True, "timeout": 4},
            )[0]
        except Exception as e:
            logger.error(f"Failed to download jwks from {signed_jwks_uri}: {e}")
    return jwks_list


class TrustChain:
    sub = None
    trust_anchor = None
    exp = None
    iat = None
    chain = None
    jwks = None
    metadata = None
    trust_marks = []
    parties_involved = None
    status = None
    log = None
    processing_start = None
    is_active = True

    def __init__(self, sub, trust_anchor, exp, iat, jwks, metadata, trust_marks=[], parties_involved=[], status="unknown", chain=[]):
        self.sub = sub
        self.trust_anchor = trust_anchor
        self.exp = exp
        self.iat = iat
        self.jwks = jwks
        self.metadata = metadata
        self.trust_marks = trust_marks
        self.parties_involved = parties_involved
        self.status = status
        self.chain = chain

    @property
    def subject(self):
        return self.sub # pragma: no cover

    @property
    def is_expired(self):
        return self.exp <= datetime.now()

    @property
    def iat_as_timestamp(self):
        return int(self.iat.timestamp())

    @property
    def exp_as_timestamp(self):
        return int(self.exp.timestamp())

    @property
    def is_valid(self):
        return self.is_active and ENTITY_STATUS[self.status]

    def __str__(self):
        return "{} [{}] [{}]".format(
            self.sub, self.trust_anchor, self.is_valid
        )

def iat_now() -> int:
    return int(datetime.now().timestamp())


def exp_from_now(minutes: int = 33) -> int:
    _now = datetime.now()
    return int((_now + timedelta(minutes=minutes)).timestamp())


def get_pkce(code_challenge_method: str = "S256", code_challenge_length: int = 64):
    hashers = {"S256": hashlib.sha256}

    code_verifier_length = random.randint(43, 128) # nosec - B311
    code_verifier = base64.urlsafe_b64encode(os.urandom(code_verifier_length)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

    code_challenge = hashers.get(code_challenge_method)(
        code_verifier.encode("utf-8")
    ).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    return {
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }


OIDCFED_ACR_PROFILES = [
    "https://www.spid.gov.it/SpidL1",
    "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3",
]

# TODO: save trust chain in the plugin storage
TRUST_CHAINS = {
    "http://cie-provider.org:8002/oidc/op": TrustChain(
        sub="http://cie-provider.org:8002/oidc/op",
        trust_anchor=OIDCFED_DEFAULT_TRUST_ANCHOR,
        exp=datetime(2022, 1, 1),
        iat=iat_now(),
        jwks=[{"kty": "RSA", "e": "AQAB", "n": "tg3aE9fd6ltXzNrim_4CGKYWfC3nqc_tv4Xjaw473CcrfiqDzeTKHfRfbvbqb1DwmI4fvCOi51EVcmKLnThzXynAUpyUvswvL8_uzgDWO1RSmBG1L0RE-CkKih4keXh1ku9hNs1_V-82dK5oLOR-VJLnhZCqThR4HH6TqLjjWrrXfsHVRvauJilX6FxGb5JFoc27VxxdH2c6P2SHC9wuB8tnfG7OSrSD1g2h7lTXbIfm78a0op67d_jupzkoKoCTmzkR2zvwTVVDd99vkDLY2WXmb8hIwG6dQZXYlkhqAYKzTuTZ0tjVh0OrqfDxYtLH3wQzzaJORewZYqLyB09P8w", "kid": "ZhSoaOedVOsBw6m2vclwSWiqqnGeOStT-gUclot_67w"}],
        metadata={"federation_entity": {"federation_resolve_endpoint": "http://cie-provider.org:8002/oidc/op/resolve", "organization_name": "CIE OIDC identity provider", "homepage_uri": "http://cie-provider.org:8002", "policy_uri": "http://cie-provider.org:8002/oidc/op/en/website/legal-information", "logo_uri": "http://cie-provider.org:8002/static/svg/logo-cie.svg", "contacts": ["tech@example.it"]}, "openid_provider": {"authorization_endpoint": "http://cie-provider.org:8002/oidc/op/authorization", "revocation_endpoint": "http://cie-provider.org:8002/oidc/op/revocation", "id_token_encryption_alg_values_supported": ["RSA-OAEP"], "id_token_encryption_enc_values_supported": ["A128CBC-HS256"], "token_endpoint": "http://cie-provider.org:8002/oidc/op/token", "userinfo_endpoint": "http://cie-provider.org:8002/oidc/op/userinfo", "introspection_endpoint": "http://cie-provider.org:8002/oidc/op/introspection", "claims_parameter_supported": True, "contacts": ["ops@https://idp.it"], "code_challenge_methods_supported": ["S256"], "client_registration_types_supported": ["automatic"], "request_authentication_methods_supported": {"ar": ["request_object"]}, "acr_values_supported": ["https://www.spid.gov.it/SpidL1", "https://www.spid.gov.it/SpidL2", "https://www.spid.gov.it/SpidL3"], "claims_supported": ["given_name", "family_name", "birthdate", "gender", "phone_number", "https://attributes.eid.gov.it/fiscal_number", "phone_number_verified", "email", "address", "document_details", "https://attributes.eid.gov.it/physical_phone_number"], "grant_types_supported": ["authorization_code", "refresh_token"], "id_token_signing_alg_values_supported": ["RS256", "ES256"], "issuer": "http://cie-provider.org:8002/oidc/op", "jwks_uri": "http://cie-provider.org:8002/oidc/op/openid_provider/jwks.json", "signed_jwks_uri": "http://cie-provider.org:8002/oidc/op/openid_provider/jwks.jose", "jwks": {"keys": [{"kty": "RSA", "use": "sig", "e": "AQAB", "n": "rJoSYv1stwlbM11tR9SYGIJuzqlJe2bv2N35oPRbwV_epjNWvGG2ZqEj53YFMC8AMZNFhuLa_LNwr1kLVE-jXQe8xjiLhe7DgMf1OnSzq9yAEXVo19BPBwkgJe2jp9HIgM_nfbIsUbSSkFAM2CKvGb0Bk2GvvqXZ12P-fpbVyA9hIQr6rNTqnCGx2-v4oViGG4u_3iTw7D1ZvLWmrmZOaKnDAqG3MJSdQ-2ggQ-Aiahg48si9C9D_JgnBV9tJ2eCS58ZC6kVG5sftElQVdH6e26mz464TZj5QgCwZCTsAQfIvBoXSdCKxpnvsFfrajz4q9BiXAryxIOl5fLmCFVNhw", "kid": "Pd2N9-TZz_AWS3GFCkoYdRaXXls8YPhx_d_Ez7JwjQI"}]}, "scopes_supported": ["openid", "offline_access"], "logo_uri": "http://cie-provider.org:8002/static/images/logo-cie.png", "organization_name": "SPID OIDC identity provider", "op_policy_uri": "http://cie-provider.org:8002/oidc/op/en/website/legal-information", "request_parameter_supported": True, "request_uri_parameter_supported": True, "require_request_uri_registration": True, "response_types_supported": ["code"], "response_modes_supported": ["query", "form_post"], "subject_types_supported": ["pairwise", "public"], "token_endpoint_auth_methods_supported": ["private_key_jwt"], "token_endpoint_auth_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"], "userinfo_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256"], "userinfo_encryption_enc_values_supported": ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"], "userinfo_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"], "request_object_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256"], "request_object_encryption_enc_values_supported": ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"], "request_object_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]}},
        parties_involved=["http://cie-provider.org:8002/oidc/op", "http://trust-anchor.org:8000"],
        status="valid",
        chain=["eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiWmhTb2FPZWRWT3NCdzZtMnZjbHdTV2lxcW5HZU9TdFQtZ1VjbG90XzY3dyJ9.eyJleHAiOjE3MDg3NTYyOTYsImlhdCI6MTcwODU4MzQ5NiwiaXNzIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wIiwic3ViIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiJ0ZzNhRTlmZDZsdFh6TnJpbV80Q0dLWVdmQzNucWNfdHY0WGphdzQ3M0NjcmZpcUR6ZVRLSGZSZmJ2YnFiMUR3bUk0ZnZDT2k1MUVWY21LTG5UaHpYeW5BVXB5VXZzd3ZMOF91emdEV08xUlNtQkcxTDBSRS1Da0tpaDRrZVhoMWt1OWhOczFfVi04MmRLNW9MT1ItVkpMbmhaQ3FUaFI0SEg2VHFMampXcnJYZnNIVlJ2YXVKaWxYNkZ4R2I1SkZvYzI3Vnh4ZEgyYzZQMlNIQzl3dUI4dG5mRzdPU3JTRDFnMmg3bFRYYklmbTc4YTBvcDY3ZF9qdXB6a29Lb0NUbXprUjJ6dndUVlZEZDk5dmtETFkyV1htYjhoSXdHNmRRWlhZbGtocUFZS3pUdVRaMHRqVmgwT3JxZkR4WXRMSDN3UXp6YUpPUmV3WllxTHlCMDlQOHciLCJraWQiOiJaaFNvYU9lZFZPc0J3Nm0ydmNsd1NXaXFxbkdlT1N0VC1nVWNsb3RfNjd3In1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL3Jlc29sdmUiLCJvcmdhbml6YXRpb25fbmFtZSI6IkNJRSBPSURDIGlkZW50aXR5IHByb3ZpZGVyIiwiaG9tZXBhZ2VfdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMiIsInBvbGljeV91cmkiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvZW4vd2Vic2l0ZS9sZWdhbC1pbmZvcm1hdGlvbiIsImxvZ29fdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9zdGF0aWMvc3ZnL2xvZ28tY2llLnN2ZyIsImNvbnRhY3RzIjpbInRlY2hAZXhhbXBsZS5pdCJdfSwib3BlbmlkX3Byb3ZpZGVyIjp7ImF1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvYXV0aG9yaXphdGlvbiIsInJldm9jYXRpb25fZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvcmV2b2NhdGlvbiIsImlkX3Rva2VuX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlNBLU9BRVAiXSwiaWRfdG9rZW5fZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4Q0JDLUhTMjU2Il0sInRva2VuX2VuZHBvaW50IjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL3Rva2VuIiwidXNlcmluZm9fZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvdXNlcmluZm8iLCJpbnRyb3NwZWN0aW9uX2VuZHBvaW50IjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL2ludHJvc3BlY3Rpb24iLCJjbGFpbXNfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwiY29udGFjdHMiOlsib3BzQGh0dHBzOi8vaWRwLml0Il0sImNvZGVfY2hhbGxlbmdlX21ldGhvZHNfc3VwcG9ydGVkIjpbIlMyNTYiXSwiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlc19zdXBwb3J0ZWQiOlsiYXV0b21hdGljIl0sInJlcXVlc3RfYXV0aGVudGljYXRpb25fbWV0aG9kc19zdXBwb3J0ZWQiOnsiYXIiOlsicmVxdWVzdF9vYmplY3QiXX0sImFjcl92YWx1ZXNfc3VwcG9ydGVkIjpbImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMSIsImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMiIsImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMyJdLCJjbGFpbXNfc3VwcG9ydGVkIjpbImdpdmVuX25hbWUiLCJmYW1pbHlfbmFtZSIsImJpcnRoZGF0ZSIsImdlbmRlciIsInBob25lX251bWJlciIsImh0dHBzOi8vYXR0cmlidXRlcy5laWQuZ292Lml0L2Zpc2NhbF9udW1iZXIiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiLCJlbWFpbCIsImFkZHJlc3MiLCJkb2N1bWVudF9kZXRhaWxzIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLmVpZC5nb3YuaXQvcGh5c2ljYWxfcGhvbmVfbnVtYmVyIl0sImdyYW50X3R5cGVzX3N1cHBvcnRlZCI6WyJhdXRob3JpemF0aW9uX2NvZGUiLCJyZWZyZXNoX3Rva2VuIl0sImlkX3Rva2VuX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJFUzI1NiJdLCJpc3N1ZXIiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AiLCJqd2tzX3VyaSI6Imh0dHA6Ly9jaWUtcHJvdmlkZXIub3JnOjgwMDIvb2lkYy9vcC9vcGVuaWRfcHJvdmlkZXIvandrcy5qc29uIiwic2lnbmVkX2p3a3NfdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL29wZW5pZF9wcm92aWRlci9qd2tzLmpvc2UiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsInVzZSI6InNpZyIsImUiOiJBUUFCIiwibiI6InJKb1NZdjFzdHdsYk0xMXRSOVNZR0lKdXpxbEplMmJ2Mk4zNW9QUmJ3Vl9lcGpOV3ZHRzJacUVqNTNZRk1DOEFNWk5GaHVMYV9MTndyMWtMVkUtalhRZTh4amlMaGU3RGdNZjFPblN6cTl5QUVYVm8xOUJQQndrZ0plMmpwOUhJZ01fbmZiSXNVYlNTa0ZBTTJDS3ZHYjBCazJHdnZxWFoxMlAtZnBiVnlBOWhJUXI2ck5UcW5DR3gyLXY0b1ZpR0c0dV8zaVR3N0QxWnZMV21ybVpPYUtuREFxRzNNSlNkUS0yZ2dRLUFpYWhnNDhzaTlDOURfSmduQlY5dEoyZUNTNThaQzZrVkc1c2Z0RWxRVmRINmUyNm16NDY0VFpqNVFnQ3daQ1RzQVFmSXZCb1hTZENLeHBudnNGZnJhano0cTlCaVhBcnl4SU9sNWZMbUNGVk5odyIsImtpZCI6IlBkMk45LVRael9BV1MzR0ZDa29ZZFJhWFhsczhZUGh4X2RfRXo3SndqUUkifV19LCJzY29wZXNfc3VwcG9ydGVkIjpbIm9wZW5pZCIsIm9mZmxpbmVfYWNjZXNzIl0sImxvZ29fdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9zdGF0aWMvaW1hZ2VzL2xvZ28tY2llLnBuZyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiU1BJRCBPSURDIGlkZW50aXR5IHByb3ZpZGVyIiwib3BfcG9saWN5X3VyaSI6Imh0dHA6Ly9jaWUtcHJvdmlkZXIub3JnOjgwMDIvb2lkYy9vcC9lbi93ZWJzaXRlL2xlZ2FsLWluZm9ybWF0aW9uIiwicmVxdWVzdF9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1ZXN0X3VyaV9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1aXJlX3JlcXVlc3RfdXJpX3JlZ2lzdHJhdGlvbiI6dHJ1ZSwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbImNvZGUiXSwicmVzcG9uc2VfbW9kZXNfc3VwcG9ydGVkIjpbInF1ZXJ5IiwiZm9ybV9wb3N0Il0sInN1YmplY3RfdHlwZXNfc3VwcG9ydGVkIjpbInBhaXJ3aXNlIiwicHVibGljIl0sInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kc19zdXBwb3J0ZWQiOlsicHJpdmF0ZV9rZXlfand0Il0sInRva2VuX2VuZHBvaW50X2F1dGhfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXSwidXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUCIsIlJTQS1PQUVQLTI1NiJdLCJ1c2VyaW5mb19lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkIjpbIkExMjhDQkMtSFMyNTYiLCJBMTkyQ0JDLUhTMzg0IiwiQTI1NkNCQy1IUzUxMiIsIkExMjhHQ00iLCJBMTkyR0NNIiwiQTI1NkdDTSJdLCJ1c2VyaW5mb19zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2IiwiUlMzODQiLCJSUzUxMiIsIkVTMjU2IiwiRVMzODQiLCJFUzUxMiJdLCJyZXF1ZXN0X29iamVjdF9lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTQS1PQUVQIiwiUlNBLU9BRVAtMjU2Il0sInJlcXVlc3Rfb2JqZWN0X2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIl0sInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJSUzM4NCIsIlJTNTEyIiwiRVMyNTYiLCJFUzM4NCIsIkVTNTEyIl19fSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAiXX0.E7g5cjdwPaFidjdGulxrlTjPKqyLjJDRDN4ViL-2vy1QzxltXu8Sy-yqH_36XwoEl6_S1qipuquEePYrQthBLwXbos3vRlH0sl8-Bxq2AwtijmGfJHLmEmK5niEBVRedADoUhrifqi27JPMgTnv_DH2XWcDbUKg64aI-6xqONY8YXtC34biS7vjCTO6rrYOQJCHHStwKQ3U6JRPVH_UrGbCUShhrrCSwHwIsGzKr3y7LpMTv908r2GgqtnPuJ9xn-2veqCyeBEJBClsRtM8HOs30MPOqdgXk2WHeSe0c6iY0k65yxWC9gP_V2EzNZZtZQgFQwEb0YQ0K5i8U7fLqqA", "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiQlh2ZnJsbmhBTXVIUjA3YWpVbUFjQlJRY1N6bXcwY19SQWdKbnBTLTlXUSJ9.eyJleHAiOjE3MDg1ODU0NzYsImlhdCI6MTcwODU4MzQ5NiwiaXNzIjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMCIsInN1YiI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6Im84SW9sUmpabGt6Y3QtNDhyaHJWbFRuWVUxcGtNYlZKRC1EVTA1b01TOVJWR3JzRnlwZzk4bS1LdzRINHFOUHlRVngyT1FPUmkteFNoZ2s3SFUtZ0tfMnBWZ3VZa3YwNkZhakxfZWRFQXFxc3F0Xzc0UWYyV0xSQzVwZkpHX3o5T1B6WThKR3lrLXozU2JlSE5fQlhLSThHWTVFNFdVMlNzdG1ROWZ5TDRDeHRSZmpVaWE4bGltVENfM01PcFQzemk1bnIwM2pmYmpwbmpnYTUxcVh1cnhubHpjM2FfeGprNVJBQXBLeFV2TndoSjI3NU0wQ21COTlEalB3RjZCTHZVZ0pxZ3lDcFVPbjM2TE9oSTRGcXVWcWhxaGl3S2xNbWlNZTN5eTB5TlE3RlhCV3hqemhleGJweWMzVnU3ekZJSFBBY0M0VXlJUWhjM3dhRWoydmlYdyIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JSUWNTem13MGNfUkFnSm5wUy05V1EifV19LCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJjb250YWN0cyI6WyJvcHNAbG9jYWxob3N0Il0sImZlZGVyYXRpb25fZmV0Y2hfZW5kcG9pbnQiOiJodHRwOi8vdHJ1c3QtYW5jaG9yLm9yZzo4MDAwL2ZldGNoIiwiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMC9yZXNvbHZlIiwiZmVkZXJhdGlvbl90cnVzdF9tYXJrX3N0YXR1c19lbmRwb2ludCI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvdHJ1c3RfbWFya19zdGF0dXMiLCJob21lcGFnZV91cmkiOiJodHRwOi8vdHJ1c3QtYW5jaG9yLm9yZzo4MDAwIiwib3JnYW5pemF0aW9uX25hbWUiOiJleGFtcGxlIFRBIiwicG9saWN5X3VyaSI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvZW4vd2Vic2l0ZS9sZWdhbC1pbmZvcm1hdGlvbiIsImxvZ29fdXJpIjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMC9zdGF0aWMvc3ZnL3NwaWQtbG9nby1jLWxiLnN2ZyIsImZlZGVyYXRpb25fbGlzdF9lbmRwb2ludCI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvbGlzdCJ9fSwidHJ1c3RfbWFya19pc3N1ZXJzIjp7Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHVibGljIjpbImh0dHBzOi8vcmVnaXN0cnkuc3BpZC5hZ2lkLmdvdi5pdCIsImh0dHBzOi8vcHVibGljLmludGVybWVkaWFyeS5zcGlkLml0Il0sImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHJpdmF0ZSI6WyJodHRwczovL3JlZ2lzdHJ5LnNwaWQuYWdpZC5nb3YuaXQiLCJodHRwczovL3ByaXZhdGUub3RoZXIuaW50ZXJtZWRpYXJ5Lml0Il0sImh0dHBzOi8vc2dkLmFhLml0L29uYm9hcmRpbmciOlsiaHR0cHM6Ly9zZ2QuYWEuaXQiXX0sImNvbnN0cmFpbnRzIjp7Im1heF9wYXRoX2xlbmd0aCI6MX19.TZM8mEg-f-Wm2MRc9EoUmBb_C-K1EJQM4NtYwiyb8buemzM5stS3sgqkDTvyBrnzd5JIzKO00CPoINX_8GxgDkOw7Y7YaOHl6ldqtGx_cIVycOnszHLnckVtpjOqit-ZvXGmpEYuM2dspoAs6Cnt1ftaWkJZm7v5BlOPviBNkzGdB2G7SOaVU99N_6QUCOc_4aieli-150ch5SjR1LtLmKpfBYrzMirLWJtB0Jay4ynS7PbGvIkNmwsGeNs21P_bFf9Zu63YJjLjAoX7e4ZTTnVhcgosLShxFPnfdu6strImkJghqn3I4wqDKCnVyMIeTqmX4h5kYPrCq0lWV09FOQ"],
    ),
}

FEDERATION_CONFIGURATIONS = [{
    "created": "2022-02-06T17:25:43.158Z",
    "modified": "2022-03-31T13:42:27.048Z",
    "uuid": "10b07ffc-5d22-4625-b5b9-d710d0b9a1de",
    "sub": "http://relying-party.org:8001",
    "default_exp": 33,
    "default_signature_alg": "RS256",
    "authority_hints": [
      "http://127.0.0.1:8000"
    ],
    "jwks_fed": [
      {
        "kty": "RSA",
        "n": "6SDksa64IjBk7HNQC7x5C9nMARGaanfaUm3wC2WulwG_8a5aIy4CEwXN2LENkCyypODqWZcTAwCzWsiihVN9kDcEs7UNu-X1WokK252D7_DRY-FXI8AB3P0CxTngs0k-OjcmbxqVW2U8G56rJFp4G_CYA4vzBoAP_5skFBt-4a5lYJlBfJ2gJlE0vh4_46oyNuUT9kmKauR7npVSHjBUSxYyDELzoaPmvR7SkX4sJe0MK39HES6s4no9G7BraLp75eOwEQmHgEhESWscSOf_CmC5ALnzWJ3FcFhxgsuMkdjoU7bH09y8pdKs64kR2znxs-yIWrPFW8hJKnySc2fk8w",
        "e": "AQAB",
        "d": "Npw19klvaNLdUWZRwe4MjPIgD8AH5BjfU5_dM05Gb6lBRWQKSWNlqP8bET-oZbWSw3zMaOAy2-k2GnYVXBYKu9WnjFFFPlbH-sVPfdKQLYzEABmxR_aaeSHrnDfKozTtFsYEgtI_WoGEaxPoE0P-Ds11Tp9h9ovZM48sDGnEdyjopnLPEZBR6VinP_yF1kfDg0kcIPmM1ZchIqJrnQpoKWeVTXtFFGrVqOAYmm4xBfP4U8TEimbeJJuYkJ9gLNnRDg_FC-ZPUiBIXigWZsEeJyevymP-NH4lq3osLgFOq0sqPxS3zkDwx9tWfT5UyqrCCortiQd2dxKzxZlEEvlQAQ",
        "p": "-1JcdcT2FdwavmPqtfOEKFUGBM9hhvwgX7KyCwl8tmresJQz8pNDkILMeKJf8ZCDVU7v4_i4C_P8oe41f2_SDsv9AIYh09zu_tQsMMdH_lqNx0YP8Yv25N5KOxnSOBO837SieFZ2xkbolXXIV7WIHrdFiyAOMOSWlETEO6JNu_M",
        "q": "7XfVt4ArSMLmRvvSl11yDF25t1aR3ylUmwZgLAJTNo76j-zo8Q2Ty7GfCIQmLOhOZTkwqnrbmwEBMEBsomWZFh_j90CLMyn1ccYUjiTI4CHJOTLMA8rYVWeArYkqek1jC4TQ9e1PkRrPcEvq2Tak8GFsBhnhOCzejJrMDgqkcwE",
        "kid": "wL_LmP8UjLVN-sAeoZ7KGEMJfBkFtbNLd24eDD9RGCs"
      }
    ],
    "jwks_core": [
      {
        "kty": "RSA",
        "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",
        "e": "AQAB",
        "d": "n_ePK5DdOxqArf75tDGaViYrXDqRVk8zyl2dfKiiR0dXQJK7tbzJtHoGQeH4E-sw3_-Bc7OKY7DcbBWgHTijMRWj9LkAu9uCvqqGMaAroWH0aBcUmZAsNjcyUIyJ3_JRcNfUDiX3nVg67qe4ZWnMDogowaVZv3aXJiCvKE8aJK4BV_nF3Nt5R6zUYpjZQ8T1GDZCV3vza3qglDrXe8zoc-p8cLs3rJn7tMVSJVznCIqOfeM1VIg0I3n2bubYOx88sckHuDnfXTiTDlyq5IwDyBHmiIe3fpu-c4e1tiBmbOf2IqDCaX8SdpnU2gTj9YlZtRNqmh3NB_rksBKWLz3uIQ",
        "p": "5PA7lJEDd3vrw5hlolFzvjvRriOu1SMHXx9Y52AgpOeQ6MnE1pO8qwn33lwYTSPGYinaq4jS3FKF_U5vOZltJAGBMa4ByEvAROJVCh958rKVRWKIqVXLOi8Gk11kHbVKw6oDXAd8Qt_y_ff8k_K6jW2EbWm1K6kfTvTMzoHkqrU",
        "q": "z2QeMH4WtrdiWUET7JgZNX0TbcaVBgd2Gpo8JHnfnGOUsvO_euKGgqpCcxiWVXSlqffQyTgVzl4iMROP8bEaQwvueHurtziMDSy9Suumyktu3PbGgjqu_izRim8Xlg7sz8Hs2quJPII_fQ8BCoaWpg30osFZqCBarQM7CWhxR40",
        "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
      }
    ],
    "trust_marks": [
      {
        "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public",
        "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvcnAvIiwiaWF0IjoxNjQ1NjEyNDAxLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.mSPNR0AOPBn3UNJAIbrWUMQ8vGTetQajpa3i59JDKDXYWqo2TUGh4AQBghCiG3qqV9cl-hleLtuwoeZ1InKHeslTLftVdcR3meeMLs3mLobHYr26Mi7pC7-jx1ZFVyk4GXl7mn9WVSQGEUOiuhL01tdlUfxf0TJSFSOMEZGpCA3hXroLOnEl3FjkAw7sPvjfImsbadbHVusb72HTTs1n5Xo7z3As3fDWHcxD-fvvq0beu9cx-L2sT4YaNC-ELd1M3m5r0NIjjEUAt4Gnot-l5Z3-C_bA41uvh2hX34U_fGZ6jpmuluJo1Lqi26N8LTB-Rbu0UMaZnkRg9E72_YRZig"
      }
    ],
    "trust_mark_issuers": {},
    "entity_type": "openid_relying_party",
    "metadata": {
      "federation_entity": {
        "federation_resolve_endpoint": "http://relying-party.org:8001/resolve",
        "organization_name": "Example RP",
        "homepage_uri": "http://relying-party.org:8001",
        "policy_uri": "http://relying-party.org:8001/en/website/legal-information",
        "logo_uri": "http://127.0.0.1:8000/static/svg/spid-logo-c-lb.svg",
        "contacts": [
          "ops@rp.example.it"
        ]
      },
      "openid_relying_party": {
        "application_type": "web",
        "organization_name": "Example RP",
        "client_id": "http://relying-party.org:8001",
        "client_registration_types": [
          "automatic"
        ],
        "jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.json",
        "signed_jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.jose",
        "jwks": {
          "keys": [
            {
              "kty": "RSA",
              "use": "sig",
              "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",
              "e": "AQAB",
              "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
            }
          ]
        },
        "client_name": "Name of an example organization",
        "contacts": [
          "ops@rp.example.it"
        ],
        "grant_types": [
          "refresh_token",
          "authorization_code"
        ],
        "redirect_uris": [
          "http://relying-party.org:8001/acl_users/oidc/callback",
          "http://relying-party.org:8001/oidc/rp/callback",
        ],
        "response_types": [
          "code"
        ],
        "subject_type": "pairwise",
        "id_token_signed_response_alg": "RS256",
        "userinfo_signed_response_alg": "RS256", 
        "userinfo_encrypted_response_alg": "RSA-OAEP", 
        "userinfo_encrypted_response_enc": "A128CBC-HS256", 
        "token_endpoint_auth_method": "private_key_jwt"
      },
    }
}]

SPID_REQUESTED_CLAIMS = {
        "id_token": {
            "given_name": {"essential": True},
            "email": {"essential": True},
        },
        "userinfo": {
            "given_name": None,
            "family_name": None,
            "email": None,
            "https://attributes.eid.gov.it/fiscal_number": None,
        },
    }

CIE_REQUESTED_CLAIMS = {
        "id_token": {"family_name": {"essential": True}, "given_name": {"essential": True}},
        "userinfo": {
            "given_name": None,
            "family_name": None,
            "email": None,
            "https://attributes.eid.gov.it/fiscal_number": None
        },
    }

RP_REQUEST_CLAIM_BY_PROFILE = {
    "spid": SPID_REQUESTED_CLAIMS,
    "cie": CIE_REQUESTED_CLAIMS,
}

RP_DEFAULT_PROVIDER_PROFILES = "cie"  # "spid"
RP_REQUEST_EXP = 60

from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse
from ..utils import create_jws, verify_jws



@implementer(IPublishTraverse)
class EntityConfiguration(BrowserView):
    """
    OIDC Federation Entity Configuration at
    .well-known/openid-federation
    """
    name = None

    def publishTraverse(self, request, name: str):
        if self.name is None:
            self.name = name
        return self

    def __call__(self):
        # TODO: pub deve essere costruita direttamente dalal configurazione del replaying party
        if self.name == "openid-federation":
            from .openidfedaration import get_federation_entity
            pub = get_federation_entity()
            conf = FEDERATION_CONFIGURATIONS[0]
            if self.request.get("format") == "json": # pragma: no cover
                self.request.response.setHeader("Content-Type", "application/json")
                return json.dumps(pub)
            else:
                self.request.response.setHeader("Content-Type", "application/entity-statement+jwt")
                return create_jws(pub, conf["jwks_fed"][0], alg=conf["default_signature_alg"], typ="entity-statement+jwt")
        else:
            raise NotFound(self.request, self.name, self.context)


class OidcRPView(BrowserView):
    def validate_json_schema(self, payload, schema_type, error_description):
        # TODO:
        return True
        # try:
        #     schema = OIDCFED_PROVIDER_PROFILES[OIDCFED_DEFAULT_PROVIDER_PROFILE]
        #     schema[schema_type](**payload)
        # except (ValidationError, Exception) as e:
        #     logger.error(
        #         f"{error_description} "
        #         f"for {payload.get('client_id', None)}: {e}"
        #     )
        #     raise ValidationException()

    def get_oidc_op(self) -> TrustChain:
        """
            get available trust to a specific OP
        """
        request = self.request
        provider = request.get("provider", None)
        if not provider:
            logger.warning(
                "Missing provider url. Please try '?provider=https://provider-subject/'"
            )
            raise InvalidTrustchain(
                "Missing provider url. Please try '?provider=https://provider-subject/'"
            )

        trust_anchor = request.get("trust_anchor", None)
        # if trust_anchor is not None and trust_anchor not in settings.OIDCFED_TRUST_ANCHORS:
        #     logger.warning("Unallowed Trust Anchor")
        #     raise InvalidTrustchain("Unallowed Trust Anchor")

        if not trust_anchor:
            for profile, value in OIDCFED_IDENTITY_PROVIDERS.items():
                if provider in value:
                    trust_anchor = value[provider]
                    break

        if not trust_anchor:
            trust_anchor = OIDCFED_DEFAULT_TRUST_ANCHOR

        tc = TRUST_CHAINS.get(provider)

        discover_trust = False
        # TODO
        if not tc:
            logger.info(f"Trust Chain not found for {provider}")
            discover_trust = True

        elif not tc.is_active:
            logger.warning(f"{tc} found but DISABLED at {tc.modified}")
            raise InvalidTrustchain(f"{tc} found but DISABLED at {tc.modified}")
        # TODO
        elif tc.is_expired:
            logger.warning(f"{tc} found but expired at {tc.exp}")
            logger.warning("Try to renew the trust chain")
            discover_trust = True

        # TODO
        # if discover_trust:
        #     tc = get_or_create_trust_chain(
        #         subject=request.GET["provider"],
        #         trust_anchor=trust_anchor,
        #         # TODO - not sure that it's required for a RP that fetches OP directly from TA
        #         # required_trust_marks = [],
        #         force=True,
        #     )
        return tc


class RequireLoginView(BrowserView):
    """Our version of the require-login view from Plone.

    Our challenge plugin redirects here.
    Note that the plugin has no way of knowing if you are authenticated:
    its code is called before this is known.
    I think.
    """

    def __call__(self):
        if api.user.is_anonymous():
            # context is our PAS plugin
            base_url = self.context.absolute_url()
            url = f"{base_url}/login"
            came_from = self.request.get("came_from", None)
            if came_from:
                url = f"{url}?came_from={quote(came_from)}"
        else:
            url = api.portal.get().absolute_url()
            url = f"{url}/insufficient-privileges"

        self.request.response.redirect(url)

class LoginView(OidcRPView):
    def _internal_redirect_location(self, session: Session) -> str:
        came_from = session.get("came_from")
        portal_url = api.portal.get_tool("portal_url")
        if not (came_from and portal_url.isURLInPortal(came_from)):
            came_from = api.portal.get().absolute_url()
        return came_from

    def __call__(self):
        """
        Redirects to the OIDC provider login page.

        For OICD Federation, the provider is specified in the provider query parameter.

            http://localhost:8080/Plone/acl_users/oidc/login?provider=http://trust-anchor.org:8000/oidc/op&profile=spid
            http://localhost:8080/Plone/acl_users/oidc/login?provider=http://cie-provider.org:8002/oidc/op&profile=cie
        """
        import pdb; pdb.set_trace()
        ## if oidc federation is enabled, we need to check the trust chain
        try:
            tc = self.get_oidc_op()
            if not tc:
                context = {
                    "error": "request rejected",
                    "error_description": "Trust Chain is unavailable.",
                }
                raise NotFound(context)
        except InvalidTrustchain as exc:
            context = {
                "error": "request rejected",
                "error_description": str(exc.args),
            }
            raise NotFound(context)
        except Exception as exc:
            context = {
                "error": "request rejected",
                "error_description": _(str(exc.args)),
            }
            raise NotFound(context)
        
        provider_metadata = tc.metadata.get('openid_provider', None)
        if not provider_metadata:
            context = {
                "error": "request rejected",
                "error_description": _("provider metadata not found"),
            }
            raise NotFound(context)

        # TODO
        entity_conf = FEDERATION_CONFIGURATIONS[0]
        # FederationEntityConfiguration.objects.filter(
        #     entity_type="openid_relying_party",
        #     # TODO: RPs multitenancy?
        #     # sub = request.build_absolute_uri()
        # ).first()
        if not entity_conf:
            context = {
                "error": "request rejected",
                "error_description": _("Missing configuration."),
            }
            raise NotFound(context)
        client_conf = entity_conf["metadata"]["openid_relying_party"]
        if not (
            provider_metadata.get("jwks_uri", None)
            or
            provider_metadata.get("jwks", None)
        ):
            context = {
                "error": "request rejected",
                "error_description": _("Invalid provider Metadata."),
            }
            raise NotFound(context)

        jwks_dict = get_jwks(provider_metadata, federation_jwks=tc.jwks)
        authz_endpoint = provider_metadata["authorization_endpoint"]
        # TODO: use format_redirect_uri (?)
        redirect_uri = self.request.get("redirect_uri", client_conf["redirect_uris"][0])
        if redirect_uri not in client_conf["redirect_uris"]:
            logger.warning(
                f"Requested for unknown redirect uri {redirect_uri}. "
                f"Reverted to default {client_conf['redirect_uris'][0]}."
            )
            redirect_uri = client_conf["redirect_uris"][0]
        _profile = self.request.get("profile", "spid")
        _timestamp_now = int(datetime.now().timestamp())
        authz_data = dict(
            iss=client_conf["client_id"],
            scope=self.request.get("scope", None) or "openid",
            redirect_uri=redirect_uri,
            response_type=client_conf["response_types"][0],
            nonce=rndstr(32),
            state=rndstr(32),
            client_id=client_conf["client_id"],
            endpoint=authz_endpoint,
            acr_values= OIDCFED_ACR_PROFILES,
            iat=_timestamp_now,
            exp =_timestamp_now + RP_REQUEST_EXP,
            jti = str(uuid.uuid4()),
            aud=[tc.sub, authz_endpoint],
            claims=RP_REQUEST_CLAIM_BY_PROFILE[_profile],
        )

        _prompt = self.request.get("prompt", "consent login")

        # if "offline_access" in authz_data["scope"]:
        # _prompt.extend(["consent login"])

        authz_data["prompt"] = _prompt

        # PKCE
        # pkce_func = import_string(RP_PKCE_CONF["function"])
        # pkce_values = pkce_func(**RP_PKCE_CONF["kwargs"])
        pkce_values = get_pkce(code_challenge_length=64, code_challenge_method="S256")

        authz_data.update(pkce_values)
        #
        authz_entry = dict(
            client_id=client_conf["client_id"],
            state=authz_data["state"],
            endpoint=authz_endpoint,
            # TODO: better have here an organization name
            provider_id=tc.sub,
            data=json.dumps(authz_data),
            provider_configuration=provider_metadata,
        )

        # save session server side or client side ?
        # Flow start
        use_session_data_manager: bool = self.context.getProperty("use_session_data_manager")
        # use_pkce: bool = self.context.getProperty("use_pkce")
        # import pdb; pdb.set_trace()
        session = Session(self.request, use_session_data_manager)
        session.set(authz_data["state"], authz_entry)
        # state is used to keep track of responses to outstanding requests (state).
        # nonce is a string value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        # session.set("authz", authz_entry)
        # session.set("state", authz_entry["state"])
        # session.set("client_id", authz_entry["client_id"])
        # session.set("data", authz_entry["data"])
        # session.set("nonce", rndstr())
        # if use_pkce:
        #     session.set("verifier", rndstr(128))

        # TODO: valutare/verificare la gestione del came_from
        # came_from = self.request.get("came_from")
        # if came_from:
        #     session.set("came_from", came_from)

        # TODO: Prune the old or unbounded authz ...
        # OidcAuthentication.objects.create(**authz_entry)
        #
        # class OidcAuthentication(models.Model):
        #     client_id = models.CharField(max_length=255)
        #     state = models.CharField(max_length=255, unique=True, default=uuid.uuid4)
        #     endpoint = models.URLField(blank=True, null=True)
        #     data = models.TextField(blank=True, null=True)
        #     successful = models.BooleanField(default=False)
        #
        #     provider_id = models.CharField(max_length=255, blank=True, null=True)
        #     provider_configuration = models.JSONField(
        #         blank=True, null=True, default=dict
        #     )
        #
        #     created = models.DateTimeField(auto_now_add=True)
        #     modified = models.DateTimeField(auto_now=True)
        #
        #     class Meta:
        #         verbose_name = "OIDC Authentication"
        #         verbose_name_plural = "OIDC Authentications"
        #
        #     def __str__(self):
        #         return f"{self.client_id} {self.state} to {self.endpoint}"

        authz_data.pop("code_verifier")
        # add the signed request object
        authz_data_obj = deepcopy(authz_data)
        authz_data_obj["iss"] = client_conf["client_id"]

        # sub claim MUST not be used to prevent that this jwt
        # could be reused as a private_key_jwt
        # authz_data_obj["sub"] = client_conf["client_id"]

        request_obj = create_jws(authz_data_obj, entity_conf["jwks_core"][0])
        authz_data["request"] = request_obj
        uri_path = urlencode(
            {
                "client_id": authz_data["client_id"],
                "scope" : authz_data["scope"],
                "response_type": authz_data["response_type"],
                "code_challenge": authz_data["code_challenge"],
                "code_challenge_method": authz_data["code_challenge_method"],
                "request": authz_data["request"]
            }
        )
        if "?" in authz_endpoint:
            qstring = "&"
        else:
            qstring = "?"
        url = qstring.join((authz_endpoint, uri_path))
        logger.info(f"Starting Authz request to {url}")
        import pdb; pdb.set_trace()
        self.request.response.redirect(url)
        return


        # ---- PLAIN OIDC ----

        session = utils.initialize_session(self.context, self.request)
        args = utils.authorization_flow_args(self.context, session)
        error_msg = ""
        try:
            client = self.context.get_oauth2_client()
        except OAuth2ConnectionException:
            client = None
            error_msg = _("There was an error getting the oauth2 client.")
        if client:
            try:
                auth_req = client.construct_AuthorizationRequest(request_args=args)
                login_url = auth_req.request(client.authorization_endpoint)
            except Exception as e:
                logger.error(e)
                error_msg = _(
                    "There was an error during the login process. Please try again."
                )
            else:
                self.request.response.setHeader(
                    "Cache-Control", "no-cache, must-revalidate"
                )
                self.request.response.redirect(login_url)

        if error_msg:
            api.portal.show_message(error_msg)
            redirect_location = self._internal_redirect_location(session)
            self.request.response.redirect(redirect_location)
        return


class LogoutView(BrowserView):
    def __call__(self):
        try:
            client = self.context.get_oauth2_client()
        except OAuth2ConnectionException:
            return ""

        # session = Session(
        #   self.request,
        #   use_session_data_manager=self.context.getProperty("use_session_data_manager")
        # )
        # state is used to keep track of responses to outstanding requests (state).
        # https://github.com/keycloak/keycloak-documentation/blob/master/securing_apps/topics/oidc/java/logout.adoc
        # session.set('end_session_state', rndstr())

        redirect_uri = utils.url_cleanup(api.portal.get().absolute_url())

        if self.context.getProperty("use_deprecated_redirect_uri_for_logout"):
            args = {
                "redirect_uri": redirect_uri,
            }
        else:
            args = {
                "post_logout_redirect_uri": redirect_uri,
                "client_id": self.context.getProperty("client_id"),
            }

        pas = api.portal.get_tool("acl_users")
        auth_cookie_name = pas.credentials_cookie_auth.cookie_name

        # end_req = client.construct_EndSessionRequest(request_args=args)
        end_req = EndSessionRequest(**args)
        logout_url = end_req.request(client.end_session_endpoint)
        self.request.response.setHeader("Cache-Control", "no-cache, must-revalidate")
        # TODO: change path with portal_path
        self.request.response.expireCookie(auth_cookie_name, path="/")
        self.request.response.expireCookie("auth_token", path="/")
        self.request.response.redirect(logout_url)
        return


class OAuth2AuthorizationCodeGrant:
    """
    https://tools.ietf.org/html/rfc6749
    """

    def access_token_request(
        self,
        redirect_uri: str,
        state: str,
        code: str,
        issuer_id: str,
        client_conf,  # : FederationEntityConfiguration,
        token_endpoint_url: str,
        audience: list,
        code_verifier: str = None,
    ):
        """
        Access Token Request
        https://tools.ietf.org/html/rfc6749#section-4.1.3
        """
        import pdb; pdb.set_trace()
        client_id=client_conf["sub"]
        grant_data = dict(
            grant_type="authorization_code",
            redirect_uri=redirect_uri,
            client_id=client_id,
            state=state,
            code=code,
            code_verifier=code_verifier,
            # here private_key_jwt
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=create_jws(
                {
                    "iss": client_id,
                    "sub": client_id,
                    "aud": [token_endpoint_url],
                    "iat": iat_now(),
                    "exp": exp_from_now(),
                    "jti": str(uuid.uuid4()),
                },
                jwk_dict=client_conf["jwks_core"][0],
            ),
        )

        logger.debug(f"Access Token Request for {state}: {grant_data} ")
        token_request = requests.post(
            token_endpoint_url,
            data=grant_data,
            # verify=HTTPC_PARAMS["connection"]["ssl"],
            # timeout=HTTPC_TIMEOUT,
        )

        if token_request.status_code != 200: # pragma: no cover
            logger.error(
                f"Something went wrong with {state}: {token_request.status_code}"
            )
        else:
            try:
                token_request = json.loads(token_request.content.decode())
            except Exception as e:  # pragma: no cover
                logger.error(f"Something went wrong with {state}: {e}")
        return token_request


class UnknownKid(Exception):
    pass


class OidcUserInfo(object):
    """
    https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    """

    def get_jwk(self, kid, jwks):
        for jwk in jwks:
            if jwk.get("kid", None) and jwk["kid"] == kid:
                return jwk
        raise UnknownKid() # pragma: no cover

    def get_userinfo(
        self, state: str, access_token: str, provider_conf: dict, verify: bool
    ):
        """
        User Info endpoint request with bearer access token
        """
        import pdb; pdb.set_trace()
        # userinfo
        headers = {"Authorization": f"Bearer {access_token}"}
        authz_userinfo = requests.get(
            provider_conf["userinfo_endpoint"],
            headers=headers,
            verify=verify,
            # timeout=getattr(
            #     settings, "HTTPC_TIMEOUT", 8
            # ) # nosec - B113
        )

        if authz_userinfo.status_code != 200: # pragma: no cover
            logger.error(
                f"Something went wrong with {state}: {authz_userinfo.status_code}"
            )
            return False
        else:
            try:
                # if application/json ... let it be
                return authz_userinfo.json()
            except Exception:
                logger.debug("userinfo response is not in plain json")

            try:
                jwe = authz_userinfo.content.decode()

                header = unpad_jwt_head(jwe)
                # header["kid"] kid di rp
                import pdb; pdb.set_trace()
                rp_jwk = self.get_jwk(header["kid"], self.rp_conf["jwks_core"])
                jws = decrypt_jwe(jwe, rp_jwk)

                if isinstance(jws, bytes):
                    jws = jws.decode()

                header = unpad_jwt_head(jws)
                idp_jwks = get_jwks(provider_conf)
                idp_jwk = self.get_jwk(header["kid"], idp_jwks)

                decoded_jwt = verify_jws(jws, idp_jwk)
                logger.debug(f"Userinfo endpoint result: {decoded_jwt}")
                return decoded_jwt

            except KeyError as e: # pragma: no cover
                logger.error(f"Userinfo response error {state}: {e}")
                return False
            except UnknownKid as e:
                logger.error(f"Userinfo Unknow KID for session {state}: {e}")
                return False
            except Exception as e:  # pragma: no cover
                logger.error(f"Userinfo response unknown error {state}: {e}")
                return False


class CallbackView(OidcRPView, OAuth2AuthorizationCodeGrant, OidcUserInfo):
    """
        View which processes an Authorization Response
        https://tools.ietf.org/html/rfc6749#section-4.1.2

        eg:
        /redirect_uri?code=tYkP854StRqBVcW4Kg4sQfEN5Qz&state=R9EVqaazGsj3wg5JgxIgm8e8U4BMvf7W
    """

    # TODO
    # def user_reunification(self, user_attrs: dict):
    #     user_model = get_user_model()

    #     if user_attrs.get(RP_USER_LOOKUP_FIELD, None):
    #         lookup = {
    #             f"attributes__{RP_USER_LOOKUP_FIELD}": user_attrs.get(RP_USER_LOOKUP_FIELD)
    #         }
    #     else:
    #         logger.warning("User attribute not found for reunification, try sub")
    #         lookup = {
    #             "username": user_attrs["username"]
    #         }
    #     user = user_model.objects.filter(**lookup).first()
    #     if user:
    #         user.attributes.update(user_attrs)
    #         user.save()
    #         logger.info(f"{RP_USER_LOOKUP_FIELD} matched on user {user}")
    #         return user
    #     elif RP_USER_CREATE:
    #         user = user_model.objects.create(
    #             username=user_attrs.get("username", user_attrs["sub"]),
    #             first_name=user_attrs.get("given_name", user_attrs["sub"]),
    #             last_name=user_attrs.get("family_name", user_attrs["sub"]),
    #             email=user_attrs.get("email", ""),
    #             attributes=user_attrs,
    #         )
    #         logger.info(f"Created new user {user}")
    #         return user

    def __call__(self):
        """
            The Authorization callback, the redirect uri where the auth code lands
        """


        import pdb; pdb.set_trace()

        # error_template = "rp_error.html"
        if "error" in self.request:
           # TODO: handle error status 401
           raise NotImplementedError("Error handling not implemented yet", self.request.get("error"))
        
        # {'code': 'c35dce7965cb5...', 
        #  'state': 'Q9wkbVdhnq2DZG7yxouoUEU8oN1GLmIs', 
        #  'iss': 'http://cie-provider.org:8002/oidc/op'}

        # search session server side
        # authz = OidcAuthentication.objects.filter(
        #     state=request_args.get("state"),
        # )

        # TODO: search session server side
        # authz = utils.load_existing_session(self.context, self.request)
        session = Session(self.request, use_session_data_manager=False)
        authz = session.get(self.request.get("state"))

        # request_args = {k: v for k, v in request.GET.items()}
        # try:
        #     self.validate_json_schema(
        #         request.GET.dict(),
        #         "authn_response",
        #         "Authn response object validation failed"
        #     )
        # except ValidationException:
        #     return JsonResponse(
        #         {
        #             "error": "invalid_request",
        #             "error_description": "Authn response object validation failed",
        #         },
        #         status = 400
        #     )

        if not authz:
            # TODO: handle error status 401
            error = {
                "error": "unauthorized request",
                "error_description": _("Authentication not found"),
            }
            raise NotFound(self.context, error)
            # return render(request, self.error_template, context, status=401)
        # else:
        #     authz = authz.last()
        # authz = authz.get("authz")

        code = self.request.get("code")
        # TODO: validate iss
        # # mixups attacks prevention
        # if request.GET.get('iss', None):
        #     if request.GET['iss'] != authz.provider_id:
        #         context = {
        #             "error": "invalid request",
        #             "error_description": _(
        #                 "authn response validation failed: mixups attack prevention."
        #             ),
        #         }
        #         return render(request, self.error_template, context, status=400)

        # authz_token = OidcAuthenticationToken.objects.create(
        #     authz_request=authz, code=code
        # )

        # TODO: cercare la configurazione del client in base al client_id dell'authz
        # XXX: questo anzichè nella call andrebbe nella init ? della vista o del plugin ?
        self.rp_conf = FEDERATION_CONFIGURATIONS[0]  # authz["client_id"]

        # self.rp_conf = FederationEntityConfiguration.objects.filter(
        #     sub=authz_token.authz_request.client_id
        # ).first()
        # if not self.rp_conf:
        #     context = {
        #         "error": "invalid request",
        #         "error_description": _("Relying party not found"),
        #     }
        #     return render(request, self.error_template, context, status=400)

        authz_data = json.loads(authz.get("data"))

        token_response = self.access_token_request(
            redirect_uri=authz_data["redirect_uri"],
            state=authz.get("state"),
            code=code,
            issuer_id=authz.get("provider_id"),
            client_conf=self.rp_conf,
            token_endpoint_url=authz.get("provider_configuration")["token_endpoint"],
            audience=[authz.get("provider_id")],
            code_verifier=authz_data.get("code_verifier"),
        )
        if not token_response:
            context = {
                "error": "invalid token response",
                "error_description": _("Token response seems not to be valid"),
            }
            # TODO: handle error status 400
            raise NotFound(self.context, context)
            # return render(request, self.error_template, context, status=400)

        else:
            # TODO
            # try:
            #     self.validate_json_schema(
            #         token_response,
            #         "token_response",
            #         "Token response object validation failed"
            #     )
            # except ValidationException:
            #     return JsonResponse(
            #         {
            #             "error": "invalid_request",
            #             "error_description": "Token response object validation failed",
            #         },
            #         status = 400
            #     )
            pass
        jwks = get_jwks(authz["provider_configuration"])
        access_token = token_response["access_token"]
        id_token = token_response["id_token"]

        op_ac_jwk = get_jwk_from_jwt(access_token, jwks)
        op_id_jwk = get_jwk_from_jwt(id_token, jwks)

        if not op_ac_jwk or not op_id_jwk:
            logger.warning(
                "Token signature validation error, "
                f"the tokens were signed with a different kid from: {jwks}."
            )
            context = {
                "error": "invalid_token",
                "error_description": _("Authentication token seems not to be valid."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        import pdb; pdb.set_trace()
        try:
            verify_jws(access_token, op_ac_jwk)
        except Exception as e:
            logger.warning(
                f"Access Token signature validation error: {e} "
            )
            context = {
                "error": "token verification failed",
                "error_description": _("Authentication token validation error."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        try:
            verify_jws(id_token, op_id_jwk)
        except Exception as e:
            logger.warning(
                f"ID Token signature validation error: {e} "
            )
            context = {
                "error": "token verification failed",
                "error_description": _("ID token validation error."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        decoded_id_token = unpad_jwt_payload(id_token)
        # logger.debug(decoded_id_token)

        try:
            verify_at_hash(decoded_id_token, access_token)
        except Exception as e:
            logger.warning(
                f"at_hash validation error: {e} "
            )
            context = {
                "error": "at_hash verification failed",
                "error_description": _("at_hash validation error."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        decoded_access_token = unpad_jwt_payload(access_token)
        # logger.debug(decoded_access_token)

        # authz_token.access_token = access_token
        # authz_token.id_token = id_token
        # authz_token.scope = token_response.get("scope")
        # authz_token.token_type = token_response["token_type"]
        # authz_token.expires_in = token_response["expires_in"]
        # authz_token.save()

        userinfo = self.get_userinfo(
            authz["state"],
            access_token,
            authz["provider_configuration"],
            verify=False,  # TODO
            # verify=HTTPC_PARAMS.get("connection", {}).get("ssl", True)
        )
        if not userinfo:
            logger.warning(
                "Userinfo request failed for state: "
                f"{authz.state} to {authz.provider_id}"
            )
            context = {
                "error": "invalid userinfo response",
                "error_description": _("UserInfo response seems not to be valid"),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=400)

        # # here django user attr mapping
        # user_attrs = process_user_attributes(userinfo, RP_ATTR_MAP, authz.__dict__)
        # if not user_attrs:
        #     _msg = "No user attributes have been processed"
        #     logger.warning(f"{_msg}: {userinfo}")
        #     # TODO: verify error message and status
        #     context = {
        #         "error": "missing user attributes",
        #         "error_description": _(f"{_msg}: {userinfo}"),
        #     }
        #     return render(request, self.error_template, context, status=403)

        # user = self.user_reunification(user_attrs)
        # if not user:
        #     # TODO: verify error message and status
        #     context = {"error": _("No user found"), "error_description": _("")}
        #     return render(request, self.error_template, context, status=403)

        # request.session["rt_expiration"] = 0

        # if token_response.get('refresh_token', None):
        #     refresh_token = token_response["refresh_token"]
        #     authz_token.refresh_token = refresh_token
        #     decoded_refresh_token = unpad_jwt_payload(refresh_token)
        #     request.session["rt_expiration"] = decoded_refresh_token['exp'] - iat_now()
        #     request.session["rt_jti"] = decoded_refresh_token['jti']
        #     logger.info(decoded_refresh_token)

        # # authenticate the user
        # login(request, user)
        # request.session["oidc_rp_user_attrs"] = user_attrs

        # request.session["at_expiration"] = decoded_access_token['exp'] - iat_now()
        # request.session["at_jti"] = decoded_access_token['jti']

        # authz_token.user = user
        # authz_token.save()
        # return HttpResponseRedirect(
        #     getattr(
        #         settings, "LOGIN_REDIRECT_URL", None
        #     ) or reverse("spid_cie_rp_echo_attributes")
        # )

        import pdb; pdb.set_trace()
        return
        # --- plain oidc ---

        session = utils.load_existing_session(self.context, self.request)
        client = self.context.get_oauth2_client()
        qs = self.request.environ["QUERY_STRING"]
        args, state = utils.parse_authorization_response(
            self.context, qs, client, session
        )
        if self.context.getProperty("use_modified_openid_schema"):
            IdToken.c_param.update(
                {
                    "email_verified": utils.SINGLE_OPTIONAL_BOOLEAN_AS_STRING,
                    "phone_number_verified": utils.SINGLE_OPTIONAL_BOOLEAN_AS_STRING,
                }
            )

        # The response you get back is an instance of an AccessTokenResponse
        # or again possibly an ErrorResponse instance.
        user_info = utils.get_user_info(client, state, args)
        if user_info:
            self.context.rememberIdentity(user_info)
            self.request.response.setHeader(
                "Cache-Control", "no-cache, must-revalidate"
            )
            return_url = utils.process_came_from(session, self.request.get("came_from"))
            self.request.response.redirect(return_url)
        else:
            raise Unauthorized()
