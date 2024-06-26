from ..jwtse import create_jws

# DEBUG from ..jwtse import verify_jws
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
        # autority_hints = ["http://trust-anchor.org:8000"]
        iat = iat_now()
        # exp = iat + 3600
        exp = iat + 172800
        portal_url = api.portal.get().absolute_url()
        sub = self.pas.get_subject()
        # https://auth.toscana.it/auth/realms/enti/federation-entity/udcvb/.well-known/openid-federation
        return {
            "exp": exp,
            "iat": iat,
            "iss": sub,
            "sub": sub,
            "jwks": {
                "keys": self.pas.get_public_jwks_fed(),
            },
            "metadata": {
                "federation_entity": {
                    "federation_resolve_endpoint": f"{sub}/resolve",
                    "organization_name": self.pas.organization_name,
                    "homepage_uri": portal_url,
                    "policy_uri": f"{portal_url}/legal-information",
                    "logo_uri": f"{portal_url}/spid-logo-c-lb.svg",
                    "contacts": [self.pas.contact],
                },
                "openid_relying_party": {
                    "application_type": "web",
                    "client_id": sub,
                    "client_registration_types": ["automatic"],
                    # "organization_name": self.pas.organization_name,
                    "jwks": {
                        "keys": self.pas.get_public_jwks_core(),
                    },
                    # "jwks_uri": f"{sub}/.well-known/jwks.json",
                    # "signed_jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.jose",
                    "client_name": self.pas.organization_name,
                    # "contacts": [self.pas.contact],
                    "grant_types": ["refresh_token", "authorization_code"],
                    "redirect_uris": [f"{sub}/callback"],
                    "response_types": self.pas.response_types,
                    "subject_type": "pairwise",
                    "id_token_signed_response_alg": "RS256",
                    "userinfo_signed_response_alg": "RS256",
                    "userinfo_encrypted_response_alg": "RSA-OAEP",
                    "userinfo_encrypted_response_enc": "A128CBC-HS256",
                    "token_endpoint_auth_method": "private_key_jwt",
                },
            },
            # "trust_marks": [
            #     # {
            #     #     "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public",
            #     #     "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvcnAvIiwiaWF0IjoxNjQ1NjEyNDAxLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.mSPNR0AOPBn3UNJAIbrWUMQ8vGTetQajpa3i59JDKDXYWqo2TUGh4AQBghCiG3qqV9cl-hleLtuwoeZ1InKHeslTLftVdcR3meeMLs3mLobHYr26Mi7pC7-jx1ZFVyk4GXl7mn9WVSQGEUOiuhL01tdlUfxf0TJSFSOMEZGpCA3hXroLOnEl3FjkAw7sPvjfImsbadbHVusb72HTTs1n5Xo7z3As3fDWHcxD-fvvq0beu9cx-L2sT4YaNC-ELd1M3m5r0NIjjEUAt4Gnot-l5Z3-C_bA41uvh2hX34U_fGZ6jpmuluJo1Lqi26N8LTB-Rbu0UMaZnkRg9E72_YRZig",
            #     # },
            #     # il trustmark è preso così, wget -O - https://preprod.oidc.registry.servizicie.interno.gov.it/fetch?sub=https://preprod.comune.serrenti.su.it/oidc&anchor=https://preprod.comune.serrenti.su.it/oidc
            #     # verificare come automtizzarlo
            #     {
            #         "trust_mark": "eyJraWQiOiJkZWZhdWx0UlNBU2lnbiIsInR5cCI6InRydXN0LW1hcmsrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJodHRwczovL3ByZXByb2QuY29tdW5lLnNlcnJlbnRpLnN1Lml0L29pZGMiLCJpc3MiOiJodHRwczovL3ByZXByb2Qub2lkYy5yZWdpc3RyeS5zZXJ2aXppY2llLmludGVybm8uZ292Lml0Iiwib3JnYW5pemF0aW9uX3R5cGUiOiJwdWJsaWMiLCJpZCI6Imh0dHBzOi8vcHJlcHJvZC5vaWRjLnJlZ2lzdHJ5LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQvb3BlbmlkX3JlbHlpbmdfcGFydHkvcHVibGljIiwiZXhwIjoxNzQyODc4ODAxLCJpYXQiOjE3MTEzNDI4MDF9.nBxGAZPhj8zSGfHyG0bgYzuo8QJRlFVV-P4aMNkiPbTs4b52qsDzR6aKnwXOnTiIjz45Y_qDrFB67d5V4YFGgqp3bgC4CtOnnGF0VQtUMWPbJgEtGHNSzBIEIyaQYpQLycV_sM27pbANgW81eugRHMhQ2IsFko4mC69Xpig3UClJ44D_Gm21iuGYb9bhvayV-mOOX9hMQpVgaQpUBfzbVt6bV5zi5KcHv-lDwARaWw4C-o-5OWvRoxuCGpNumTuNgYqbqLlxzUzIBkGA92g8CeFYvGUVQcxSnmAMmnm-Zt5NolvRqfjybHY85OMD4KFFKOGz51Rw9EbBltPoBRAMGQ",
            #         "iss": "https://preprod.oidc.registry.servizicie.interno.gov.it",
            #         "id": "https://preprod.oidc.registry.servizicie.interno.gov.it/openid_relying_party/public",
            #     },
            # ],
            "trust_marks": json.loads(self.pas.trust_marks),
            "authority_hints": list(self.pas.autority_hints),
        }

    def __call__(self):
        if self.name == "openid-federation":
            pub = self.openid_federation()
            # conf = FEDERATION_CONFIGURATIONS[0]
            if self.request.get("format") == "json":  # pragma: no cover
                self.request.response.setHeader("Content-Type", "application/json")
                return json.dumps(pub)
            else:
                self.request.response.setHeader(
                    "Content-Type", "application/entity-statement+jwt"
                )
                jws = create_jws(
                    pub,
                    self.pas.get_private_jwks_fed()[0],
                    alg="RS256",  # conf["default_signature_alg"],
                    typ="entity-statement+jwt",
                )
                # DEBUG
                # verify_jws(jws, self.pas.get_public_jwks_fed()[0])
                return jws
        elif self.name == "jwks.json":
            self.request.response.setHeader("Content-Type", "application/json")
            return json.dumps(
                {
                    "keys": self.pas.get_public_jwks_core(),
                }
            )
        else:
            raise NotFound(self.request, self.name, self.context)
