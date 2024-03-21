# spid_cie_oidc/entity/jwtse.py
from cryptojwt.exception import UnsupportedAlgorithm
from cryptojwt.exception import VerificationError
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.utils import left_hash
from pas.plugins.oidc import logger
from pas.plugins.oidc.config import SIGNING_ALG_VALUES_SUPPORTED

import base64
import binascii
import json


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


def create_jws(
    payload: dict, jwk_dict: dict, alg: str = "RS256", protected: dict = {}, **kwargs
) -> str:
    _key = key_from_jwk_dict(jwk_dict)
    _signer = JWS(payload, alg=alg, **kwargs)

    signature = _signer.sign_compact([_key], protected=protected, **kwargs)
    return signature


def verify_jws(jws: str, pub_jwk: dict, **kwargs) -> str:
    _key = key_from_jwk_dict(pub_jwk)

    _head = unpad_jwt_head(jws)
    if _head.get("kid") != pub_jwk["kid"]:  # pragma: no cover
        raise Exception(f"kid error: {_head.get('kid')} != {pub_jwk['kid']}")

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


def verify_at_hash(id_token, access_token) -> bool:
    id_token_at_hash = id_token["at_hash"]
    at_hash = left_hash(access_token, "HS256")
    if at_hash != id_token_at_hash:
        raise Exception(f"at_hash error: {at_hash} != {id_token_at_hash}")
    return True


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
