# TODO: pub deve essere costruita direttamente dalal configurazione del replaying party
# pub = get_federation_entity()
# conf = FEDERATION_CONFIGURATIONS[0]
from ..config import FEDERATION_CONFIGURATIONS
from ..jwtse import create_jws
from ..utils import iat_now
from plone import api
from Products.Five.browser import BrowserView
from zExceptions import NotFound
from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse

import json


@implementer(IPublishTraverse)
class EntityConfiguration(BrowserView):
    """
    OIDC Federation Entity Configuration at
    .well-known/openid-federation
    """

    name = None

    @property
    def pas(self):
        # return api.portal.get_tool("acl_users")
        return self.context

    def publishTraverse(self, request, name: str):
        if self.name is None:
            self.name = name
        return self

    def openid_federation(self):
        autority_hints = ["https://oidc.registry.servizicie.interno.gov.it"]
        # autority_hints = ["http://trust-anchor.org:8000"]
        iat = iat_now()
        # exp = iat + 3600
        exp = iat + 172800
        portal_url = api.portal.get().absolute_url()
        sub = f"{portal_url}/oidc"
        # https://auth.toscana.it/auth/realms/enti/federation-entity/udcvb/.well-known/openid-federation
        return {
            "exp": exp,
            "iat": iat,
            "iss": sub,
            "sub": sub,
            "jwks": {
                "keys": self.pas.get_public_jwks(),
            },
            "metadata": {
                # "federation_entity": {
                #     "federation_resolve_endpoint": f"{sub}/resolve",
                #     "organization_name": self.pas.organization_name,
                #     "homepage_uri": portal_url,
                #     # "policy_uri": f"{portal_url}/legal-information",
                #     # "logo_uri": "http://trust-anchor.org:8000/static/svg/spid-logo-c-lb.svg",
                #     "contacts": [self.pas.contact],
                # },
                "openid_relying_party": {
                    "application_type": "web",
                    "organization_name": self.pas.organization_name,
                    "client_id": sub,
                    "client_registration_types": ["automatic"],
                    # "jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.json",
                    # "signed_jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.jose",
                    "jwks": {
                        "keys": self.pas.get_public_jwks(),
                    },
                    "client_name": self.pas.organization_name,
                    "contacts": [self.pas.contact],
                    "grant_types": ["refresh_token", "authorization_code"],
                    "redirect_uris": [f"{sub}/callback"],
                    "response_types": ["code"],
                    "subject_type": "pairwise",
                    "id_token_signed_response_alg": "RS256",
                    "userinfo_signed_response_alg": "RS256",
                    "userinfo_encrypted_response_alg": "RSA-OAEP",
                    "userinfo_encrypted_response_enc": "A128CBC-HS256",
                    # "token_endpoint_auth_method": "private_key_jwt",
                },
            },
            "trust_marks": [
                {
                    "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public",
                    "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvcnAvIiwiaWF0IjoxNjQ1NjEyNDAxLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.mSPNR0AOPBn3UNJAIbrWUMQ8vGTetQajpa3i59JDKDXYWqo2TUGh4AQBghCiG3qqV9cl-hleLtuwoeZ1InKHeslTLftVdcR3meeMLs3mLobHYr26Mi7pC7-jx1ZFVyk4GXl7mn9WVSQGEUOiuhL01tdlUfxf0TJSFSOMEZGpCA3hXroLOnEl3FjkAw7sPvjfImsbadbHVusb72HTTs1n5Xo7z3As3fDWHcxD-fvvq0beu9cx-L2sT4YaNC-ELd1M3m5r0NIjjEUAt4Gnot-l5Z3-C_bA41uvh2hX34U_fGZ6jpmuluJo1Lqi26N8LTB-Rbu0UMaZnkRg9E72_YRZig",
                }
            ],
            "authority_hints": autority_hints,
        }

    def __call__(self):
        if self.name == "openid-federation":
            pub = self.openid_federation()
            conf = FEDERATION_CONFIGURATIONS[0]
            if self.request.get("format") == "json":  # pragma: no cover
                self.request.response.setHeader("Content-Type", "application/json")
                return json.dumps(pub)
            else:
                self.request.response.setHeader(
                    "Content-Type", "application/entity-statement+jwt"
                )
                return create_jws(
                    pub,
                    conf["jwks_fed"][0],
                    alg=conf["default_signature_alg"],
                    typ="entity-statement+jwt",
                )
        else:
            raise NotFound(self.request, self.name, self.context)
