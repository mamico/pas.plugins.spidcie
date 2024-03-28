from ..jwtse import create_jws
from ..jwtse import verify_jws
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
            "trust_marks": [
                # {
                #     "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public",
                #     "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvcnAvIiwiaWF0IjoxNjQ1NjEyNDAxLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.mSPNR0AOPBn3UNJAIbrWUMQ8vGTetQajpa3i59JDKDXYWqo2TUGh4AQBghCiG3qqV9cl-hleLtuwoeZ1InKHeslTLftVdcR3meeMLs3mLobHYr26Mi7pC7-jx1ZFVyk4GXl7mn9WVSQGEUOiuhL01tdlUfxf0TJSFSOMEZGpCA3hXroLOnEl3FjkAw7sPvjfImsbadbHVusb72HTTs1n5Xo7z3As3fDWHcxD-fvvq0beu9cx-L2sT4YaNC-ELd1M3m5r0NIjjEUAt4Gnot-l5Z3-C_bA41uvh2hX34U_fGZ6jpmuluJo1Lqi26N8LTB-Rbu0UMaZnkRg9E72_YRZig",
                # },
                # il trustmark è preso così, wget -O - https://preprod.oidc.registry.servizicie.interno.gov.it/fetch?sub=https://preprod.comune.serrenti.su.it/oidc&anchor=https://preprod.comune.serrenti.su.it/oidc
                # verificare come automtizzarlo
                {
                    "id": "https://preprod.oidc.registry.servizicie.interno.gov.it/openid_relying_party/public",
                    "iss": "https://preprod.oidc.registry.servizicie.interno.gov.it",
                    "trust_mark": "eyJraWQiOiJkZWZhdWx0UlNBU2lnbiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJodHRwczovL3ByZXByb2QuY29tdW5lLnNlcnJlbnRpLnN1Lml0L29pZGMiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwia2lkIjoidnZWTW50REJMWmxkYV94MUVoQnQxWXhMYnB2SWM0OVRKUUJIRmVBOWFncyIsIm4iOiJtWkMzN2ZHTXYxYmszZFBOZUFmYnFlaWNoZHhEdlQwS3lZNnNYXzhqelZ0bW9FQTQ3R2MzcjYya2J0Z3JvaUNPX2ZuNFoxU2FpLVgxSjJTVXc5MEZBU2I2Z1NTMGhXQnZzNUhSbFhTQWNhSDRiaWtBaGNiMENkT2xVUW5ZelhkdjNpTTY2dGR6YW54a3l6NW55T25tbEgxcHFfUlA4bVB0V0lWdV9nY2hOQU91NHFHSHBJbFJQaDNaOXUyWHlBdkR6TmZtSHUwLVUyRm5OYXBLT0N6N1RoUE1VMzJGTVF2X0FPaTRKY1VHMTdydXcwY0s4RUJQWFlRTlZJRVdfU1owUDJ1VjhpRklwLXp1cjVVSXAwdXM3MFpfQlk3a25xSS15TWN6V0ZEQWtIcjBHT0ZXTFp1NzdOX1cyV1NvcllRdTFobE92NnBXcC1RVElNZmdIY0dNZlEifV19LCJtZXRhZGF0YV9wb2xpY3kiOnsib3BlbmlkX3JlbHlpbmdfcGFydHkiOnsiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlcyI6eyJzdWJzZXRfb2YiOlsiYXV0b21hdGljIl0sImVzc2VudGlhbCI6dHJ1ZX0sImdyYW50X3R5cGVzIjp7InN1cGVyc2V0X29mIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJzdWJzZXRfb2YiOlsiYXV0aG9yaXphdGlvbl9jb2RlIiwicmVmcmVzaF90b2tlbiJdfSwiandrcyI6eyJ2YWx1ZSI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6IjV5NzJ4Y2N1cVFfZzR4SUdvTnV2S3NOb2YybzhXNzNTV0Yxd195QmpjYjAiLCJuIjoidmNIbEM1WjdBNmdKaU9LdWVxd0RaMnRtMldDWkNkTDh4NlpXemJfMC1VV2xwWEU0SGs0UXNJY05vRXpDY2dkSWRxWklMMWNNZUl0cFdzLUxMVmY1bmV3bUhlTTlWRnMtMUhyeTRjUGp5N3d5NGhjel9VZ3RMY0cxS2t2dk5MUHplV0l6YjFUT0xQMEV6eklyN0FlU1BLMEhSRnRMNVM2elNuUV9KSlA0Y3F5NnNYMzJCRG9jbFp0YnZrUDJBa1l2OEduaTd1SnE0QTg0VTFIZ080cmJTUkI4UkN4TTNBQVk2NWhILVhiR09RT05qLUdoNlV4UE9QNHQzU2Z2anA1THlXelJKdDVUOGxobnp1QURCanZyN1NlWGJWbFU0Tk9naFcxdHJhMVpPZFVJdnBYUjlldkI3UzRBU185Z0xLamcwNUVEMUdnZ3BIcU1vZVR5Nk0ydGx3In0seyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6ImVuYyIsImtpZCI6Ik5ldEpQN0ZpSkdVaUFObE9XRU85bUNnYTlFX1RlN01HbXd5cjdNLVBmN0UiLCJhbGciOiJSU0EtT0FFUCIsIm4iOiJubkdCMUtpUjRFTU1udjMtTmdFNEdHWW04WkRNS3dQaHFmTXU5U1pmMF91c1cxVC1WUEpLcjQyaGJsSFlLemdmZm9aVHlsNE5rUnVxUjZtVHhVcVRNX3AwS2pLSG4tQWdick9hVEctZXlrYWtkci1FOC1NUnZ2TXAzYXRLeVIzRjVYVEJQcjEtSElQd0hQR3lnTXJNTFVIZ2UxNzA3TnZuZUR2ZzF6Qy1KX1Y5RlFWQXhrZDZVSzBsdkxlM0hoLUlJZ0tVdzIxZHVSSGZCem41LU11ZlRsa0lsMmpySWpPQmZyMDZvUU5BX0NEQzBBdzR4aXFwYVdtbTlQUFN4YmM3TUZTdjlTM1BTQ3RnMmtYaVFqVzBHZFlwa2JzSFRGbHVJSUxJWEw5YWtjalRJT0s2RWUzbEVldHRaU2FWRlphYloxcV9CNE51UjYtb2pRX0ZHR3U4WHcifV19fSwidXNlcmluZm9fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6eyJvbmVfb2YiOlsiQTEyOENCQy1IUzI1NiIsIkEyNTZDQkMtSFM1MTIiXSwiZXNzZW50aWFsIjp0cnVlfSwidXNlcmluZm9fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6eyJvbmVfb2YiOlsiUlNBLU9BRVAiLCJSU0EtT0FFUC0yNTYiLCJFQ0RILUVTIiwiRUNESC1FUytBMTI4S1ciLCJFQ0RILUVTK0EyNTZLVyJdLCJlc3NlbnRpYWwiOnRydWV9LCJyZWRpcmVjdF91cmlzIjp7ImVzc2VudGlhbCI6dHJ1ZX0sInVzZXJpbmZvX3NpZ25lZF9yZXNwb25zZV9hbGciOnsib25lX29mIjpbIlJTMjU2IiwiUlM1MTIiLCJFUzI1NiIsIkVTNTEyIiwiUFMyNTYiLCJQUzUxMiJdLCJlc3NlbnRpYWwiOnRydWV9LCJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZCI6eyJvbmVfb2YiOlsicHJpdmF0ZV9rZXlfand0Il0sImVzc2VudGlhbCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJlc3NlbnRpYWwiOnRydWV9LCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjp7Im9uZV9vZiI6WyJSU0EtT0FFUCIsIlJTQS1PQUVQLTI1NiIsIkVDREgtRVMiLCJFQ0RILUVTK0ExMjhLVyIsIkVDREgtRVMrQTI1NktXIl0sImVzc2VudGlhbCI6ZmFsc2V9LCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjp7Im9uZV9vZiI6WyJBMTI4Q0JDLUhTMjU2IiwiQTI1NkNCQy1IUzUxMiJdLCJlc3NlbnRpYWwiOmZhbHNlfSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6eyJvbmVfb2YiOlsiUlMyNTYiLCJSUzUxMiIsIkVTMjU2IiwiRVM1MTIiLCJQUzI1NiIsIlBTNTEyIl0sImVzc2VudGlhbCI6dHJ1ZX0sInJlc3BvbnNlX3R5cGVzIjp7InZhbHVlIjpbImNvZGUiXX19fSwiaXNzIjoiaHR0cHM6Ly9wcmVwcm9kLm9pZGMucmVnaXN0cnkuc2Vydml6aWNpZS5pbnRlcm5vLmdvdi5pdCIsImV4cCI6MTcxMTYzNDY3MywiaWF0IjoxNzExNDYxODczLCJ0cnVzdF9tYXJrcyI6W3sidHJ1c3RfbWFyayI6ImV5SnJhV1FpT2lKa1pXWmhkV3gwVWxOQlUybG5iaUlzSW5SNWNDSTZJblJ5ZFhOMExXMWhjbXNyYW5kMElpd2lZV3huSWpvaVVsTXlOVFlpZlEuZXlKemRXSWlPaUpvZEhSd2N6b3ZMM0J5WlhCeWIyUXVZMjl0ZFc1bExuTmxjbkpsYm5ScExuTjFMbWwwTDI5cFpHTWlMQ0pwYzNNaU9pSm9kSFJ3Y3pvdkwzQnlaWEJ5YjJRdWIybGtZeTV5WldkcGMzUnllUzV6WlhKMmFYcHBZMmxsTG1sdWRHVnlibTh1WjI5MkxtbDBJaXdpYjNKbllXNXBlbUYwYVc5dVgzUjVjR1VpT2lKd2RXSnNhV01pTENKcFpDSTZJbWgwZEhCek9pOHZjSEpsY0hKdlpDNXZhV1JqTG5KbFoybHpkSEo1TG5ObGNuWnBlbWxqYVdVdWFXNTBaWEp1Ynk1bmIzWXVhWFF2YjNCbGJtbGtYM0psYkhscGJtZGZjR0Z5ZEhrdmNIVmliR2xqSWl3aVpYaHdJam94TnpReU9EYzRPREF4TENKcFlYUWlPakUzTVRFek5ESTRNREY5Lm5CeEdBWlBoajh6U0dmSHlHMGJnWXp1bzhRSlJsRlZWLVA0YU1Oa2lQYlRzNGI1MnFzRHpSNmFLbndYT25UaUlqejQ1WV9xRHJGQjY3ZDVWNFlGR2dxcDNiZ0M0Q3RPbm5HRjBWUXRVTVdQYkpnRXRHSE5TekJJRUl5YVFZcFFMeWNWX3NNMjdwYkFOZ1c4MWV1Z1JITWhRMklzRmtvNG1DNjlYcGlnM1VDbEo0NERfR20yMWl1R1liOWJodmF5Vi1tT09YOWhNUXBWZ2FRcFVCZnpiVnQ2YlY1emk1S2NIdi1sRHdBUmFXdzRDLW8tNU9XdlJveHVDR3BOdW1UdU5nWXFicUxseHpVeklCa0dBOTJnOENlRll2R1VWUWN4U25tQU1tbm0tWnQ1Tm9sdlJxZmp5YkhZODVPTUQ0S0ZGS09HejUxUnc5RWJCbHRQb0JSQU1HUSIsImlzcyI6Imh0dHBzOi8vcHJlcHJvZC5vaWRjLnJlZ2lzdHJ5LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQiLCJpZCI6Imh0dHBzOi8vcHJlcHJvZC5vaWRjLnJlZ2lzdHJ5LnNlcnZpemljaWUuaW50ZXJuby5nb3YuaXQvb3BlbmlkX3JlbHlpbmdfcGFydHkvcHVibGljIn1dfQ.CZ_y9sFnLNWSx0lf6azbLgfH1q-GkBnxfIQpdOXNNDJ90iRHBpHQaW9BqSr5fJDzlrMJbzySdhyMdLzo5Bfk8On8duJXcrGc2zZ9AVqIbRlBvf_Ys-EBHu6aap3CxyVLEkasgOvKkD-wPwkT2_WTp-jValGanpUrAOqlkAwBM0lscn5SzkxZkC9_Ca9VxnT-9bXdNbbXeE2mZA3nGiSQZj6Qm6ezjxJ5lQN9gaOAOf_IntjQKIoTFoybBb8ODzsKVI6xx-EwaEl_csmeDgixiShchDjHeq8eOtWPQ4M1yxbgeZWo5TpD_dQhB0L4-OVIkJeNmFo4bLWgmyHWJPUGmg"
                },
            ],
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
