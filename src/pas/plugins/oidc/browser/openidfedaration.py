def get_federation_entity(entity_id: str=None) -> dict:
    """
    Retrieve the federation entity metadata for the given entity ID.
    """
    return {
        "exp": 1709546145,
        "iat": 1709544165,
        "iss": "http://relying-party.org:8001",
        "sub": "http://relying-party.org:8001",
        "jwks": {
            "keys": [
                {
                    "kty": "RSA",
                    "n": "6SDksa64IjBk7HNQC7x5C9nMARGaanfaUm3wC2WulwG_8a5aIy4CEwXN2LENkCyypODqWZcTAwCzWsiihVN9kDcEs7UNu-X1WokK252D7_DRY-FXI8AB3P0CxTngs0k-OjcmbxqVW2U8G56rJFp4G_CYA4vzBoAP_5skFBt-4a5lYJlBfJ2gJlE0vh4_46oyNuUT9kmKauR7npVSHjBUSxYyDELzoaPmvR7SkX4sJe0MK39HES6s4no9G7BraLp75eOwEQmHgEhESWscSOf_CmC5ALnzWJ3FcFhxgsuMkdjoU7bH09y8pdKs64kR2znxs-yIWrPFW8hJKnySc2fk8w",
                    "e": "AQAB",
                    "kid": "wL_LmP8UjLVN-sAeoZ7KGEMJfBkFtbNLd24eDD9RGCs",
                }
            ]
        },
        "metadata": {
            "federation_entity": {
                "federation_resolve_endpoint": "http://relying-party.org:8001/resolve",
                "organization_name": "Example RP",
                "homepage_uri": "http://relying-party.org:8001",
                "policy_uri": "http://relying-party.org:8001/en/website/legal-information",
                "logo_uri": "http://trust-anchor.org:8000/static/svg/spid-logo-c-lb.svg",
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
                "redirect_uris": ["http://relying-party.org:8001/oidc/rp/callback"],
                "response_types": ["code"],
                "subject_type": "pairwise",
                "id_token_signed_response_alg": "RS256",
                "userinfo_signed_response_alg": "RS256",
                "userinfo_encrypted_response_alg": "RSA-OAEP",
                "userinfo_encrypted_response_enc": "A128CBC-HS256",
                "token_endpoint_auth_method": "private_key_jwt",
            },
        },
        "trust_marks": [
            {
                "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public",
                "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvcnAvIiwiaWF0IjoxNjQ1NjEyNDAxLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.mSPNR0AOPBn3UNJAIbrWUMQ8vGTetQajpa3i59JDKDXYWqo2TUGh4AQBghCiG3qqV9cl-hleLtuwoeZ1InKHeslTLftVdcR3meeMLs3mLobHYr26Mi7pC7-jx1ZFVyk4GXl7mn9WVSQGEUOiuhL01tdlUfxf0TJSFSOMEZGpCA3hXroLOnEl3FjkAw7sPvjfImsbadbHVusb72HTTs1n5Xo7z3As3fDWHcxD-fvvq0beu9cx-L2sT4YaNC-ELd1M3m5r0NIjjEUAt4Gnot-l5Z3-C_bA41uvh2hX34U_fGZ6jpmuluJo1Lqi26N8LTB-Rbu0UMaZnkRg9E72_YRZig",
            }
        ],
        "authority_hints": ["http://trust-anchor.org:8000"],
    }
