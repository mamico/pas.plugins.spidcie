# ---------------------------------------------------------------
# TODO: move to settings

# required for onboarding checks and also for all the leafs
OIDCFED_DEFAULT_TRUST_ANCHOR = "http://trust-anchor.org:8000"

OIDCFED_IDENTITY_PROVIDERS = {
    #   "spid": {
    #     "http://127.0.0.1:8000/oidc/op" : OIDCFED_DEFAULT_TRUST_ANCHOR,
    #   },
    "cie": {
        "http://cie-provider.org:8002/oidc/op": OIDCFED_DEFAULT_TRUST_ANCHOR,
    }
}
# ---------------------------------------------------------------

ENTITY_STATUS = {
    "unreachable": False,
    "valid": True,
    "signature_failed": False,
    "not_valid": False,
    "unknown": None,
    "expired": None,
}

SIGNING_ALG_VALUES_SUPPORTED = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

OIDCFED_TRUST_ANCHORS = [OIDCFED_DEFAULT_TRUST_ANCHOR]

FEDERATION_DEFAULT_EXP = 2880

# TODO: estendere
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

# TODO: estendere
CIE_REQUESTED_CLAIMS = {
    "id_token": {"family_name": {"essential": True}, "given_name": {"essential": True}},
    "userinfo": {
        "given_name": None,
        "family_name": None,
        "email": None,
        "https://attributes.eid.gov.it/fiscal_number": None,
    },
}

RP_REQUEST_CLAIM_BY_PROFILE = {
    "spid": SPID_REQUESTED_CLAIMS,
    "cie": CIE_REQUESTED_CLAIMS,
}

RP_DEFAULT_PROVIDER_PROFILES = "cie"  # "spid"
RP_REQUEST_EXP = 60


OIDCFED_ACR_PROFILES = [
    "https://www.spid.gov.it/SpidL1",
    "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3",
]

FEDERATION_CONFIGURATIONS = [
    {
        "created": "2022-02-06T17:25:43.158Z",
        "modified": "2022-03-31T13:42:27.048Z",
        "uuid": "10b07ffc-5d22-4625-b5b9-d710d0b9a1de",
        "sub": "http://relying-party.org:8001",
        "default_exp": 33,
        "default_signature_alg": "RS256",
        "authority_hints": ["http://127.0.0.1:8000"],
        "jwks_fed": [
            {
                "kty": "RSA",
                "n": "6SDksa64IjBk7HNQC7x5C9nMARGaanfaUm3wC2WulwG_8a5aIy4CEwXN2LENkCyypODqWZcTAwCzWsiihVN9kDcEs7UNu-X1WokK252D7_DRY-FXI8AB3P0CxTngs0k-OjcmbxqVW2U8G56rJFp4G_CYA4vzBoAP_5skFBt-4a5lYJlBfJ2gJlE0vh4_46oyNuUT9kmKauR7npVSHjBUSxYyDELzoaPmvR7SkX4sJe0MK39HES6s4no9G7BraLp75eOwEQmHgEhESWscSOf_CmC5ALnzWJ3FcFhxgsuMkdjoU7bH09y8pdKs64kR2znxs-yIWrPFW8hJKnySc2fk8w",
                "e": "AQAB",
                "d": "Npw19klvaNLdUWZRwe4MjPIgD8AH5BjfU5_dM05Gb6lBRWQKSWNlqP8bET-oZbWSw3zMaOAy2-k2GnYVXBYKu9WnjFFFPlbH-sVPfdKQLYzEABmxR_aaeSHrnDfKozTtFsYEgtI_WoGEaxPoE0P-Ds11Tp9h9ovZM48sDGnEdyjopnLPEZBR6VinP_yF1kfDg0kcIPmM1ZchIqJrnQpoKWeVTXtFFGrVqOAYmm4xBfP4U8TEimbeJJuYkJ9gLNnRDg_FC-ZPUiBIXigWZsEeJyevymP-NH4lq3osLgFOq0sqPxS3zkDwx9tWfT5UyqrCCortiQd2dxKzxZlEEvlQAQ",
                "p": "-1JcdcT2FdwavmPqtfOEKFUGBM9hhvwgX7KyCwl8tmresJQz8pNDkILMeKJf8ZCDVU7v4_i4C_P8oe41f2_SDsv9AIYh09zu_tQsMMdH_lqNx0YP8Yv25N5KOxnSOBO837SieFZ2xkbolXXIV7WIHrdFiyAOMOSWlETEO6JNu_M",
                "q": "7XfVt4ArSMLmRvvSl11yDF25t1aR3ylUmwZgLAJTNo76j-zo8Q2Ty7GfCIQmLOhOZTkwqnrbmwEBMEBsomWZFh_j90CLMyn1ccYUjiTI4CHJOTLMA8rYVWeArYkqek1jC4TQ9e1PkRrPcEvq2Tak8GFsBhnhOCzejJrMDgqkcwE",
                "kid": "wL_LmP8UjLVN-sAeoZ7KGEMJfBkFtbNLd24eDD9RGCs",
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
                "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs",
            }
        ],
        "trust_marks": [
            {
                "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public",
                "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvcnAvIiwiaWF0IjoxNjQ1NjEyNDAxLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.mSPNR0AOPBn3UNJAIbrWUMQ8vGTetQajpa3i59JDKDXYWqo2TUGh4AQBghCiG3qqV9cl-hleLtuwoeZ1InKHeslTLftVdcR3meeMLs3mLobHYr26Mi7pC7-jx1ZFVyk4GXl7mn9WVSQGEUOiuhL01tdlUfxf0TJSFSOMEZGpCA3hXroLOnEl3FjkAw7sPvjfImsbadbHVusb72HTTs1n5Xo7z3As3fDWHcxD-fvvq0beu9cx-L2sT4YaNC-ELd1M3m5r0NIjjEUAt4Gnot-l5Z3-C_bA41uvh2hX34U_fGZ6jpmuluJo1Lqi26N8LTB-Rbu0UMaZnkRg9E72_YRZig",
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
                "contacts": ["ops@rp.example.it"],
            },
            "openid_relying_party": {
                "application_type": "web",
                "organization_name": "Example RP",
                "client_id": "http://relying-party.org:8001",
                "client_registration_types": ["automatic"],
                "jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.json",
                "signed_jwks_uri": "http://relying-party.org:8001/oidc/rp/openid_relying_party/jwks.jose",
                "jwks": {
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",
                            "e": "AQAB",
                            "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs",
                        }
                    ]
                },
                "client_name": "Name of an example organization",
                "contacts": ["ops@rp.example.it"],
                "grant_types": ["refresh_token", "authorization_code"],
                "redirect_uris": [
                    "http://relying-party.org:8001/acl_users/oidc/callback",
                    "http://relying-party.org:8001/oidc/rp/callback",
                ],
                "response_types": ["code"],
                "subject_type": "pairwise",
                "id_token_signed_response_alg": "RS256",
                "userinfo_signed_response_alg": "RS256",
                "userinfo_encrypted_response_alg": "RSA-OAEP",
                "userinfo_encrypted_response_enc": "A128CBC-HS256",
                "token_endpoint_auth_method": "private_key_jwt",
            },
        },
    }
]
