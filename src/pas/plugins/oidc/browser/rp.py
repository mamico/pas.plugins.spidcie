from ..config import OIDCFED_DEFAULT_TRUST_ANCHOR
from ..config import OIDCFED_IDENTITY_PROVIDERS
from ..config import OIDCFED_TRUST_ANCHORS
from ..exceptions import InvalidTrustchain
from ..exceptions import UnknownKid
from ..jwtse import create_jws
from ..jwtse import decrypt_jwe
from ..jwtse import unpad_jwt_head
from ..jwtse import verify_jws
from ..trustchain import TrustChain
from ..utils import exp_from_now
from ..utils import get_jwks
from ..utils import iat_now

# from pas.plugins.oidc import _
from pas.plugins.oidc import logger
from Products.Five.browser import BrowserView
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile

import json
import requests
import uuid


class OidcRPView(BrowserView):
    """base class for OIDC RP views"""

    error_page = ViewPageTemplateFile("templates/error.pt")

    @property
    def pas(self):
        # TODO: se si sposta la vista va cercato/calcolato il PAS
        return self.context

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
        if trust_anchor is not None and trust_anchor not in OIDCFED_TRUST_ANCHORS:
            logger.warning("Unallowed Trust Anchor %s", trust_anchor)
            raise InvalidTrustchain("Unallowed Trust Anchor")

        if not trust_anchor:
            for profile, value in OIDCFED_IDENTITY_PROVIDERS.items():
                if provider in value:
                    trust_anchor = value[provider]
                    break

        if not trust_anchor:
            trust_anchor = OIDCFED_DEFAULT_TRUST_ANCHOR

        tc = self.pas.get_trust_chain(provider, trust_anchor)
        # tc = TrustChain.objects.filter(
        #     sub=request.GET["provider"],
        #     trust_anchor__sub=trust_anchor,
        # ).first()

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

        if discover_trust:
            # tc = get_or_create_trust_chain(
            #     subject=request.GET["provider"],
            #     trust_anchor=trust_anchor,
            #     # TODO - not sure that it's required for a RP that fetches OP directly from TA
            #     # required_trust_marks = [],
            #     force=True,
            # )
            tc = self.pas.get_or_create_trust_chain(provider, trust_anchor)
        return tc


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
        client_id = client_conf["sub"]
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

        if token_request.status_code != 200:  # pragma: no cover
            logger.error(
                f"Something went wrong with {state}: {token_request.status_code}"
            )
        else:
            try:
                token_request = json.loads(token_request.content.decode())
            except Exception as e:  # pragma: no cover
                logger.error(f"Something went wrong with {state}: {e}")
        return token_request


class OidcUserInfo(object):
    """
    https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    """

    def get_jwk(self, kid, jwks):
        for jwk in jwks:
            if jwk.get("kid", None) and jwk["kid"] == kid:
                return jwk
        raise UnknownKid()  # pragma: no cover

    def get_userinfo(
        self, state: str, access_token: str, provider_conf: dict, verify: bool
    ):
        """
        User Info endpoint request with bearer access token
        """
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

        if authz_userinfo.status_code != 200:  # pragma: no cover
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

            except KeyError as e:  # pragma: no cover
                logger.error(f"Userinfo response error {state}: {e}")
                return False
            except UnknownKid as e:
                logger.error(f"Userinfo Unknow KID for session {state}: {e}")
                return False
            except Exception as e:  # pragma: no cover
                logger.error(f"Userinfo response unknown error {state}: {e}")
                return False
