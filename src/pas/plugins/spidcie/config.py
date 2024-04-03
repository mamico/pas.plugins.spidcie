# ---------------------------------------------------------------
# TODO: move to settings

# required for onboarding checks and also for all the leafs
# OIDCFED_DEFAULT_TRUST_ANCHOR = "http://trust-anchor.org:8000"

# TODO: questo dovrebbe dinamico usando il trust anchor
# https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/trust_negotiation.html#relying-party
# https://oidc.registry.servizicie.interno.gov.it/list?entity_type=openid_provider

OIDCFED_IDENTITY_PROVIDERS = {
    #   "spid": {
    #     "http://127.0.0.1:8000/oidc/op" : OIDCFED_DEFAULT_TRUST_ANCHOR,
    #   },
    "cie": {
        # "http://cie-provider.org:8002/oidc/op": "http://trust-anchor.org:8000",
        "https://preproduzione.oidc.idserver.servizicie.interno.gov.it": "https://preprod.oidc.registry.servizicie.interno.gov.it",
        "https://oidc.idserver.servizicie.interno.gov.it": "https://oidc.registry.servizicie.interno.gov.it",
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

# OIDCFED_TRUST_ANCHORS = [OIDCFED_DEFAULT_TRUST_ANCHOR]

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
RP_REQUEST_EXP = 3600  # 1 hour (TODO: verificare)


OIDCFED_ACR_PROFILES = [
    "https://www.spid.gov.it/SpidL1",
    "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3",
]
