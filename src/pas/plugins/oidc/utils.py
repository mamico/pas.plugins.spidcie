from hashlib import sha256
from oic import rndstr
from oic.exception import RequestError
from oic.oic import message
from pas.plugins.oidc import logger
from pas.plugins.oidc import PLUGIN_ID
from pas.plugins.oidc import plugins
from pas.plugins.oidc.session import Session
from plone import api
from typing import Union

import base64
import re
from secrets import token_hex
# from spid_cie_oidc.entity.jwtse import unpad_jwt_head
# from spid_cie_oidc.entity.settings import HTTPC_PARAMS
# from spid_cie_oidc.entity.statements import get_http_url

from datetime import timedelta

import datetime
import json
import logging

logger = logging.getLogger(__name__)


def boolean_string_ser(val, sformat=None, lev=0):
    bool_value = bool(val)
    return bool_value


def boolean_string_deser(val, sformat=None, lev=0):
    if isinstance(val, bool):
        return val
    else:
        if val.lower() == "true":
            return True

    return False


# value type, required, serializer, deserializer, null value allowed
SINGLE_OPTIONAL_BOOLEAN_AS_STRING = message.ParamDefinition(
    str, False, boolean_string_ser, boolean_string_deser, False
)


class CustomOpenIDNonBooleanSchema(message.OpenIDSchema):
    c_param = {
        "sub": message.SINGLE_REQUIRED_STRING,
        "name": message.SINGLE_OPTIONAL_STRING,
        "given_name": message.SINGLE_OPTIONAL_STRING,
        "family_name": message.SINGLE_OPTIONAL_STRING,
        "middle_name": message.SINGLE_OPTIONAL_STRING,
        "nickname": message.SINGLE_OPTIONAL_STRING,
        "preferred_username": message.SINGLE_OPTIONAL_STRING,
        "profile": message.SINGLE_OPTIONAL_STRING,
        "picture": message.SINGLE_OPTIONAL_STRING,
        "website": message.SINGLE_OPTIONAL_STRING,
        "email": message.SINGLE_OPTIONAL_STRING,
        "email_verified": SINGLE_OPTIONAL_BOOLEAN_AS_STRING,
        "gender": message.SINGLE_OPTIONAL_STRING,
        "birthdate": message.SINGLE_OPTIONAL_STRING,
        "zoneinfo": message.SINGLE_OPTIONAL_STRING,
        "locale": message.SINGLE_OPTIONAL_STRING,
        "phone_number": message.SINGLE_OPTIONAL_STRING,
        "phone_number_verified": SINGLE_OPTIONAL_BOOLEAN_AS_STRING,
        "address": message.OPTIONAL_ADDRESS,
        "updated_at": message.SINGLE_OPTIONAL_INT,
        "_claim_names": message.OPTIONAL_MESSAGE,
        "_claim_sources": message.OPTIONAL_MESSAGE,
    }


_URL_MAPPING = (
    (r"(.*)/api($|/.*)", r"\1\2"),
    (r"(.*)/\+\+api\+\+($|/.*)", r"\1\2"),
)


def url_cleanup(url: str) -> str:
    """Clean up redirection url."""
    # Volto frontend mapping exception
    for search, replace in _URL_MAPPING:
        match = re.search(search, url)
        if match:
            url = re.sub(search, replace, url)
    return url


def get_plugin() -> plugins.OIDCPlugin:
    """Return the OIDC plugin for the current portal."""
    pas = api.portal.get_tool("acl_users")
    return getattr(pas, PLUGIN_ID)


# Flow: Start
def initialize_session(plugin: plugins.OIDCPlugin, request) -> Session:
    """Initialize a Session."""
    use_session_data_manager: bool = plugin.getProperty("use_session_data_manager")
    use_pkce: bool = plugin.getProperty("use_pkce")
    session = Session(request, use_session_data_manager)
    # state is used to keep track of responses to outstanding requests (state).
    # nonce is a string value used to associate a Client session with an ID Token, and to mitigate replay attacks.
    session.set("state", rndstr())
    session.set("nonce", rndstr())
    came_from = request.get("came_from")
    if came_from:
        session.set("came_from", came_from)
    if use_pkce:
        session.set("verifier", rndstr(128))
    return session


def pkce_code_verifier_challenge(value: str) -> str:
    """Build a sha256 hash of the base64 encoded value of value

    Be careful: this should be url-safe base64 and we should also remove the trailing '='
    See https://www.stefaanlippens.net/oauth-code-flow-pkce.html#PKCE-code-verifier-and-challenge
    """
    hash_code = sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(hash_code).decode("utf-8").replace("=", "")


def authorization_flow_args(plugin: plugins.OIDCPlugin, session: Session) -> dict:
    """Return the arguments used for the authorization flow."""
    # https://pyoidc.readthedocs.io/en/latest/examples/rp.html#authorization-code-flow
    args = {
        "client_id": plugin.getProperty("client_id"),
        "response_type": "code",
        "scope": plugin.get_scopes(),
        "state": session.get("state"),
        "nonce": session.get("nonce"),
        "redirect_uri": plugin.get_redirect_uris(),
    }
    if plugin.getProperty("use_pkce"):
        # Build a random string of 43 to 128 characters
        # and send it in the request as a base64-encoded urlsafe string of the sha256 hash of that string
        args["code_challenge"] = pkce_code_verifier_challenge(session.get("verifier"))
        args["code_challenge_method"] = "S256"
    return args


# Flow: Process
def load_existing_session(plugin: plugins.OIDCPlugin, request) -> Session:
    use_session_data_manager: bool = plugin.getProperty("use_session_data_manager")
    session = Session(request, use_session_data_manager)
    return session


def parse_authorization_response(
    plugin: plugins.OIDCPlugin, qs: str, client, session: Session
) -> tuple:
    """Parse a flow response and return arguments for client calls."""
    use_pkce: bool = plugin.getProperty("use_pkce")
    aresp = client.parse_response(
        message.AuthorizationResponse, info=qs, sformat="urlencoded"
    )
    aresp_state = aresp["state"]
    session_state = session.get("state")
    if aresp_state != session_state:
        logger.error(
            f"Invalid OAuth2 state response: {aresp_state}" f"session: {session_state}"
        )
        # TODO: need to double check before removing the comment below
        # raise ValueError("invalid OAuth2 state")

    args = {
        "code": aresp["code"],
        "redirect_uri": plugin.get_redirect_uris(),
    }

    if use_pkce:
        args["code_verifier"] = session.get("verifier")
    return args, aresp["state"]


def get_user_info(client, state, args) -> Union[message.OpenIDSchema, dict]:
    resp = client.do_access_token_request(
        state=state,
        request_args=args,
        authn_method="client_secret_basic",
    )
    user_info = {}
    if isinstance(resp, message.AccessTokenResponse):
        # If it's an AccessTokenResponse the information in the response will be stored in the
        # client instance with state as the key for future use.
        user_info = resp.to_dict().get("id_token", {})
        if client.userinfo_endpoint:
            # https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

            # XXX: Not completely sure if this is even needed
            #      We do not have a OpenID connect provider with userinfo endpoint
            #      enabled and with the weird treatment of boolean values, so we cannot test this
            # if self.context.getProperty("use_modified_openid_schema"):
            #     userinfo = client.do_user_info_request(state=aresp["state"], user_info_schema=CustomOpenIDNonBooleanSchema)
            # else:
            #     userinfo = client.do_user_info_request(state=aresp["state"])
            try:
                user_info = client.do_user_info_request(state=state)
            except RequestError as exc:
                logger.error(
                    "Authentication failed, probably missing openid scope",
                    exc_info=exc,
                )
                user_info = {}
        # userinfo in an instance of OpenIDSchema or ErrorResponse
        # It could also be dict, if there is no userinfo_endpoint
        if not (user_info and isinstance(user_info, (message.OpenIDSchema, dict))):
            logger.error(f"Authentication failed,  invalid response {resp} {user_info}")
            user_info = {}
    elif isinstance(resp, message.TokenErrorResponse):
        logger.error(f"Token error response: {resp.to_json()}")
    else:
        logger.error(f"Authentication failed {resp}")
    return user_info


def process_came_from(session: Session, came_from: str = "") -> str:
    if not came_from:
        came_from = session.get("came_from")
    portal_url = api.portal.get_tool("portal_url")
    if not (came_from and portal_url.isURLInPortal(came_from)):
        came_from = api.portal.get().absolute_url()
    return url_cleanup(came_from)

# --- SPID/CIE OIDC FED

SIGNING_ALG_VALUES_SUPPORTED = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

# utils.py

def iat_now() -> int:
    return int(datetime.now().timestamp())


def exp_from_now(minutes: int = 33) -> int:
    _now = datetime.now()
    return int((_now + timedelta(minutes=minutes)).timestamp())


def datetime_from_timestamp(value) -> datetime.datetime:
    return make_aware(datetime.datetime.fromtimestamp(value))


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
                [jwks_uri], httpc_params=HTTPC_PARAMS
            )
            jwks_list = json.loads(jwks_list[0])
        except Exception as e:
            logger.error(f"Failed to download jwks from {jwks_uri}: {e}")
    elif metadata.get('signed_jwks_uri'):
        try:
            signed_jwks_uri = metadata["signed_jwks_uri"]
            jwks_list = get_http_url(
                [signed_jwks_uri], httpc_params=HTTPC_PARAMS
            )[0]
        except Exception as e:
            logger.error(f"Failed to download jwks from {signed_jwks_uri}: {e}")
    return jwks_list


def get_jwk_from_jwt(jwt: str, provider_jwks: dict) -> dict:
    """
        docs here
    """
    head = unpad_jwt_head(jwt)
    kid = head["kid"]
    if isinstance(provider_jwks, dict) and provider_jwks.get('keys'):
        provider_jwks = provider_jwks['keys']
    for jwk in provider_jwks:
        if jwk["kid"] == kid:
            return jwk
    return {}


def random_token(n=254):
    return token_hex(n)

from plone.app.event.base import FALLBACK_TIMEZONE
from plone.app.event.base import replacement_zones
from plone.event.utils import default_timezone as fallback_default_timezone
from plone.event.utils import validated_timezone
from zope.component import getUtility
from plone.registry.interfaces import IRegistry


def make_aware(value, timezone=None):
    """Make a naive datetime.datetime in a given time zone aware.

    https://github.com/django/django/blob/main/django/utils/timezone.py
    """
    if timezone is None:
        timezone = get_current_timezone()
    # Check that we won't overwrite the timezone of an aware datetime.
    if is_aware(value):
        raise ValueError("make_aware expects a naive datetime, got %s" % value)
    # This may be wrong around DST changes!
    return value.replace(tzinfo=timezone)

def is_aware(value):
    """
    Determine if a given datetime.datetime is aware.

    The concept is defined in Python's docs:
    https://docs.python.org/library/datetime.html#datetime.tzinfo

    Assuming value.tzinfo is either None or a proper datetime.tzinfo,
    value.utcoffset() implements the appropriate logic.

    https://github.com/django/django/blob/main/django/utils/timezone.py
    """
    return value.utcoffset() is not None


def datetime_from_timestamp(value) -> datetime.datetime:
    return make_aware(datetime.datetime.fromtimestamp(value))


def get_current_timezone():
    """Get the current timezone from the registry or the default timezone."""
    reg_key = "plone.portal_timezone"
    registry = getUtility(IRegistry)
    portal_timezone = registry.get(reg_key, None)
    # fallback to what plone.event is doing
    if not portal_timezone:
        portal_timezone = fallback_default_timezone()

    # Change any ambiguous timezone abbreviations to their most common
    # non-ambigious timezone name.
    if portal_timezone in replacement_zones.keys():
        portal_timezone = replacement_zones[portal_timezone]
    portal_timezone = validated_timezone(portal_timezone, FALLBACK_TIMEZONE)
    return portal_timezone


# jwtse.py
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS
from cryptojwt.exception import UnsupportedAlgorithm, VerificationError

def create_jws(payload: dict, jwk_dict: dict, alg: str = "RS256", protected:dict = {}, **kwargs) -> str:
    _key = key_from_jwk_dict(jwk_dict)
    _signer = JWS(payload, alg=alg, **kwargs)

    signature = _signer.sign_compact([_key], protected=protected, **kwargs)
    return signature


def verify_jws(jws: str, pub_jwk: dict, **kwargs) -> str:
    _key = key_from_jwk_dict(pub_jwk)

    _head = unpad_jwt_head(jws)
    if _head.get("kid") != pub_jwk["kid"]:  # pragma: no cover
        raise Exception(
            f"kid error: {_head.get('kid')} != {pub_jwk['kid']}"
        )

    _alg = _head["alg"]
    if _alg not in SIGNING_ALG_VALUES_SUPPORTED or not _alg:  # pragma: no cover
        raise UnsupportedAlgorithm(f"{_alg} has beed disabled for security reason")

    verifier = JWS(alg=_head["alg"], **kwargs)
    msg = verifier.verify_compact(jws, [_key])
    return msg

def unpad_jwt_element(jwt: str, position: int) -> dict:
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def unpad_jwt_head(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=0)


def unpad_jwt_payload(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=1)

from cryptojwt.jws.utils import left_hash


def verify_at_hash(id_token, access_token) -> bool:
    id_token_at_hash = id_token['at_hash']
    at_hash = left_hash(access_token, "HS256")
    if at_hash != id_token_at_hash:
        raise Exception(
            f"at_hash error: {at_hash} != {id_token_at_hash}"
        )
    return True

import binascii
DEFAULT_JWS_ALG = "RS256"
DEFAULT_JWE_ALG = "RSA-OAEP"
DEFAULT_JWE_ENC = "A256CBC-HS512"
ENCRYPTION_ALG_VALUES_SUPPORTED = [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ]
from cryptojwt.jwe.jwe import factory

def decrypt_jwe(jwe: str, jwk_dict: dict) -> dict:
    # get header
    try:
        jwe_header = unpad_jwt_head(jwe)
    except (binascii.Error, Exception) as e:  # pragma: no cover
        logger.error(f"Failed to extract JWT header: {e}")
        raise VerificationError("The JWT is not valid")

    _alg = jwe_header.get("alg", DEFAULT_JWE_ALG)
    _enc = jwe_header.get("enc", DEFAULT_JWE_ENC)
    jwe_header.get("kid")

    if _alg not in ENCRYPTION_ALG_VALUES_SUPPORTED:  # pragma: no cover
        raise UnsupportedAlgorithm(f"{_alg} has beed disabled for security reason")

    _decryptor = factory(jwe, alg=_alg, enc=_enc)

    # _dkey = RSAKey(priv_key=PRIV_KEY)
    _dkey = key_from_jwk_dict(jwk_dict)
    msg = _decryptor.decrypt(jwe, [_dkey])

    try:
        msg_dict = json.loads(msg)
        logger.debug(f"Decrypted JWT as: {json.dumps(msg_dict, indent=2)}")
    except json.decoder.JSONDecodeError:
        msg_dict = msg
        logger.debug(f"Decrypted JWT as: {msg_dict}")
    return msg_dict
