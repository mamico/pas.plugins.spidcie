from .config import ENTITY_STATUS

# from .config import OIDCFED_DEFAULT_TRUST_ANCHOR
from .exceptions import InvalidEntityConfiguration
from .exceptions import InvalidRequiredTrustMark
from .exceptions import InvalidTrustchain
from .exceptions import MetadataDiscoveryException
from .exceptions import TrustchainMissingMetadata
from .policy import apply_policy
from .statements import EntityConfiguration
from .statements import get_entity_configurations
from .utils import datetime_from_timestamp

# from .utils import iat_now
from collections import OrderedDict
from datetime import datetime
try:
    from datetime import UTC
except ImportError:
    from datetime import timezone
    UTC = timezone.utc

import logging


logger = logging.getLogger(__name__)


class FetchedEntityStatement:
    """
    Entity Statement acquired by a third party
    """

    def __init__(self, iss, sub, exp, iat, statement, jwt=None):
        """
        :param iss: URL that identifies the issuer of this statement in the Federation.
        :param sub: URL that identifies this Entity in the Federation.
        :param exp: Expiration time of the statement
        :param iat: Issued At time of the statement
        :param statement: Entity statement
        :param jwt: JWT of the statement
        """
        self.iss = iss
        self.sub = sub
        self.exp = exp
        self.iat = iat
        self.statement = statement
        self.jwt = jwt

    def get_entity_configuration_as_obj(self):
        return EntityConfiguration(self.jwt)

    @property
    def is_expired(self):
        return self.exp <= datetime.now(UTC)

    def __str__(self):
        return f"{self.sub} issued by {self.iss}"


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

    def __init__(
        self,
        sub,
        trust_anchor,
        exp,
        jwks,
        metadata,
        trust_marks=[],
        parties_involved=[],
        status="unknown",
        chain=[],
        processing_start=None,
        is_active=True,
    ):
        self.sub = sub
        self.trust_anchor = trust_anchor
        self.exp = exp
        self.iat = datetime.now(UTC)
        self.jwks = jwks
        self.metadata = metadata
        self.trust_marks = trust_marks
        self.parties_involved = parties_involved
        self.status = status
        self.chain = chain
        self.processing_start = processing_start
        self.is_active = is_active

    @property
    def subject(self):
        return self.sub  # pragma: no cover

    @property
    def is_expired(self):
        return self.exp <= datetime.now(UTC)

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
        return "{} [{}] [{}]".format(self.sub, self.trust_anchor, self.is_valid)

    def update(self, **kwargs):
        # TODO: update the trust chain in the plugin storage
        # import pdb; pdb.set_trace()
        pass


def get_or_create_trust_chain(
    pas,
    subject: str,
    trust_anchor: str,
    required_trust_marks: list = [],
    force: bool = False,
) -> TrustChain:
    """
    returns a TrustChain model object if any available
    if available it return it
    if not available it create a new one

    if available and expired it return the expired one
    if flag force is set to True -> renew the trust chain, update it and
    return the updated one
    """
    # fetched_trust_anchor = FetchedEntityStatement.objects.filter(
    #     sub=trust_anchor, iss=trust_anchor
    # )
    fetched_trust_anchor = pas.get_fetched_entity_statement(trust_anchor)

    if not fetched_trust_anchor or fetched_trust_anchor.is_expired or force:
        jwts = get_entity_configurations([trust_anchor])
        ta_conf = EntityConfiguration(jwts[0])

        data = dict(
            exp=datetime_from_timestamp(ta_conf.payload["exp"]),
            iat=datetime_from_timestamp(ta_conf.payload["iat"]),
            statement=ta_conf.payload,
            jwt=ta_conf.jwt,
        )

        if not fetched_trust_anchor:
            # trust to the anchor should be absolute trusted!
            # ta_conf.validate_by_itself()
            # fetched_trust_anchor = FetchedEntityStatement.objects.create(
            fetched_trust_anchor = pas.create_fetched_entity_statement(
                ta_conf.sub,
                ta_conf.iss,
                FetchedEntityStatement(sub=ta_conf.sub, iss=ta_conf.iss, **data),
            )
        else:
            # fetched_trust_anchor.update(
            fetched_trust_anchor = pas.update_fetched_entity_statement(
                fetched_trust_anchor,
                exp=datetime_from_timestamp(ta_conf.payload["exp"]),
                iat=datetime_from_timestamp(ta_conf.payload["iat"]),
                statement=ta_conf.payload,
                jwt=ta_conf.jwt,
            )
            # fetched_trust_anchor = fetched_trust_anchor.first()
    else:
        # fetched_trust_anchor = fetched_trust_anchor.first()
        ta_conf = fetched_trust_anchor.get_entity_configuration_as_obj()

    # tc = TrustChain.objects.filter(sub=subject, trust_anchor__sub=trust_anchor).first()
    tc = pas.get_trust_chain(subject, trust_anchor)

    if tc and not tc.is_active:
        # if manualy disabled by staff
        return None
    elif force or not tc or tc.is_expired:
        tc_builder = trust_chain_builder(
            subject=subject,
            trust_anchor=ta_conf,
            required_trust_marks=required_trust_marks,
        )
        if not tc_builder:
            raise InvalidTrustchain(
                f"Trust chain for subject {subject} and "
                f"trust_anchor {trust_anchor} is not found"
            )
        elif not tc_builder.is_valid:
            raise InvalidTrustchain(
                f"Trust chain for subject {subject} and "
                f"trust_anchor {trust_anchor} is not valid"
            )
        elif not tc_builder.final_metadata:
            raise TrustchainMissingMetadata(
                f"Trust chain for subject {subject} and "
                f"trust_anchor {trust_anchor} doesn't have any metadata"
            )

        # TODO: is it needed ?
        # dumps_statements_from_trust_chain_to_db(trust_chain)

        # tc = TrustChain.objects.filter(
        #     sub=subject, trust_anchor__sub=trust_anchor
        # )
        data = dict(
            exp=tc_builder.exp_datetime,
            processing_start=datetime.now(UTC),
            chain=tc_builder.serialize(),
            jwks=tc_builder.subject_configuration.jwks,
            metadata=tc_builder.final_metadata,
            parties_involved=[i.sub for i in tc_builder.trust_path],
            status="valid",
            trust_marks=[
                {"id": i.id, "trust_mark": i.jwt}
                for i in tc_builder.verified_trust_marks
            ],
            is_active=True,
        )

        if tc:
            # TODO: update ?
            tc.update(**data)
            # tc = tc.first()
        else:
            # tc = TrustChain.objects.create(
            #     sub=subject,
            #     trust_anchor=fetched_trust_anchor,
            #     **data,
            # )
            tc = TrustChain(
                sub=subject,
                trust_anchor=fetched_trust_anchor,
                **data,
            )
            pas.set_trust_chain(subject, tc)

    return tc


def trust_chain_builder(
    subject: str, trust_anchor: EntityConfiguration, required_trust_marks: list = []
):
    """
    Trust Chain builder
    """
    tc = TrustChainBuilder(
        subject,
        trust_anchor=trust_anchor,
        required_trust_marks=required_trust_marks,
    )
    tc.start()

    if not tc.is_valid:
        logger.error(
            "The tree of trust cannot be validated for "
            f"{tc.subject}: {tc.tree_of_trust}"
        )
        return False
    else:
        return tc


class TrustChainBuilder:
    """
    A trust walker that fetches statements and evaluate the evaluables

    max_intermediaries means how many hops are allowed to the trust anchor
    max_authority_hints means how much authority_hints to follow on each hop

    required_trust_marks means all the trsut marks needed to start a metadata discovery
     at least one of the required trust marks is needed to start a metadata discovery
     if this param if absent the filter won't be considered.
    """

    def __init__(
        self,
        subject: str,
        trust_anchor,  # : Union[str, EntityConfiguration],
        httpc_params: dict = {},
        max_authority_hints: int = 10,
        subject_configuration: EntityConfiguration = None,
        required_trust_marks: list = [],
        # TODO - prefetch cache?
        # pre_fetched_entity_configurations = {},
        # pre_fetched_statements = {},
        #
        **kwargs,
    ) -> None:

        self.subject = subject
        self.subject_configuration = subject_configuration
        self.httpc_params = httpc_params

        self.trust_anchor = trust_anchor
        self.trust_anchor_configuration = None

        self.required_trust_marks = required_trust_marks
        self.is_valid = False

        self.tree_of_trust = OrderedDict()
        self.trust_path = []  # list of valid subjects up to trust anchor

        self.max_authority_hints = max_authority_hints
        # dynamically valued
        self.max_path_len = 0
        self.final_metadata: dict = {}

        self.verified_trust_marks = []
        self.exp = 0

    def apply_metadata_policy(self) -> dict:
        """
        filters the trust path from subject to trust anchor
        apply the metadata policies along the path and
        returns the final metadata
        """
        # find the path of trust
        if not self.trust_path:
            self.trust_path = [self.subject_configuration]
        elif self.trust_path[-1].sub == self.trust_anchor_configuration.sub:
            # ok trust path completed, I just have to return over all the parent calls
            return

        logger.info(
            f"Applying metadata policy for {self.subject} over "
            f"{self.trust_anchor_configuration.sub} starting from "
            f"{self.trust_path[-1]}"
        )
        last_path = self.tree_of_trust[len(self.trust_path) - 1]

        path_found = False
        for ec in last_path:
            for sup_ec in ec.verified_by_superiors.values():
                while len(self.trust_path) - 2 < self.max_path_len:
                    if sup_ec.sub == self.trust_anchor_configuration.sub:
                        self.trust_path.append(sup_ec)
                        path_found = True
                        break
                    if sup_ec.verified_by_superiors:
                        self.trust_path.append(sup_ec)
                        self.apply_metadata_policy()
                    else:
                        logger.info(
                            f"'Cul de sac' in {sup_ec.sub} for {self.subject} "
                            f"to {self.trust_anchor_configuration.sub}"
                        )
                        self.trust_path = [self.subject_configuration]
                        break

        # once I filtered a concrete and unique trust path I can apply the metadata policy
        if path_found:
            logger.info(f"Found a trust path: {self.trust_path}")
            self.final_metadata = self.subject_configuration.payload.get("metadata", {})
            if not self.final_metadata:
                logger.error(
                    f"Missing metadata in {self.subject_configuration.payload['metadata']}"
                )
                return

            for i in range(len(self.trust_path))[::-1]:
                self.trust_path[i - 1].sub
                _pol = self.trust_path[i].verified_descendant_statements.get(
                    "metadata_policy", {}
                )
                for md_type, md in _pol.items():
                    if not self.final_metadata.get(md_type):
                        continue
                    self.final_metadata[md_type] = apply_policy(
                        self.final_metadata[md_type], _pol[md_type]
                    )

        # set exp
        self.set_exp()
        return self.final_metadata

    @property
    def exp_datetime(self) -> datetime:
        if self.exp:  # pragma: no cover
            return datetime_from_timestamp(self.exp)

    def set_exp(self) -> int:
        exps = [i.payload["exp"] for i in self.trust_path]
        if exps:
            self.exp = min(exps)

    def discovery(self) -> bool:
        """
        return a chain of verified statements
        from the lower up to the trust anchor
        """
        logger.info(f"Starting a Walk into Metadata Discovery for {self.subject}")
        self.tree_of_trust[0] = [self.subject_configuration]

        ecs_history = []
        while (len(self.tree_of_trust) - 2) < self.max_path_len:
            last_path_n = list(self.tree_of_trust.keys())[-1]
            last_ecs = self.tree_of_trust[last_path_n]

            sup_ecs = []
            for last_ec in last_ecs:
                # Metadata discovery loop prevention
                if last_ec.sub in ecs_history:
                    logger.warning(
                        f"Metadata discovery loop detection for {last_ec.sub}. "
                        f"Already present in {ecs_history}. "
                        "Discovery blocked for this path."
                    )
                    continue

                try:
                    superiors = last_ec.get_superiors(
                        max_authority_hints=self.max_authority_hints,
                        superiors_hints=[self.trust_anchor_configuration],
                    )
                    validated_by = last_ec.validate_by_superiors(
                        superiors_entity_configurations=superiors.values()
                    )
                    vbv = list(validated_by.values())
                    sup_ecs.extend(vbv)
                    ecs_history.append(last_ec)
                except MetadataDiscoveryException as e:
                    logger.exception(
                        f"Metadata discovery exception for {last_ec.sub}: {e}"
                    )

            if sup_ecs:
                self.tree_of_trust[last_path_n + 1] = sup_ecs
            else:
                break

        last_path = list(self.tree_of_trust.keys())[-1]
        if (
            self.tree_of_trust[0][0].is_valid
            and self.tree_of_trust[last_path][0].is_valid
        ):
            self.is_valid = True
            self.apply_metadata_policy()

        return self.is_valid

    def get_trust_anchor_configuration(self) -> None:
        if isinstance(self.trust_anchor, EntityConfiguration):
            self.trust_anchor_configuration = self.trust_anchor

        elif not self.trust_anchor_configuration and isinstance(self.trust_anchor, str):
            logger.info(f"Starting Metadata Discovery for {self.subject}")
            ta_jwt = get_entity_configurations(
                self.trust_anchor, httpc_params=self.httpc_params
            )[0]
            self.trust_anchor_configuration = EntityConfiguration(ta_jwt)

        try:
            self.trust_anchor_configuration.validate_by_itself()
        except Exception as e:  # pragma: no cover
            _msg = (
                f"Trust Anchor Entity Configuration failed for {self.trust_anchor}. "
                f"{e}"
            )
            logger.error(_msg)
            raise Exception(_msg)

        if self.trust_anchor_configuration.payload.get("constraints", {}).get(
            "max_path_length"
        ):
            self.max_path_len = int(
                self.trust_anchor_configuration.payload["constraints"][
                    "max_path_length"
                ]
            )

    def get_subject_configuration(self) -> None:
        if not self.subject_configuration:
            try:
                jwt = get_entity_configurations(
                    self.subject, httpc_params=self.httpc_params
                )
                self.subject_configuration = EntityConfiguration(
                    jwt[0], trust_anchor_entity_conf=self.trust_anchor_configuration
                )
                self.subject_configuration.validate_by_itself()
            except Exception as e:
                _msg = f"Entity Configuration for {self.subject} failed: {e}"
                logger.error(_msg)
                raise InvalidEntityConfiguration(_msg)

            # Trust Mark filter
            if self.required_trust_marks:
                sc = self.subject_configuration
                sc.filter_by_allowed_trust_marks = self.required_trust_marks

                # TODO: create a proxy function that gets tm issuers ec from
                # a previously populated cache
                # sc.trust_mark_issuers_entity_confs = [
                # trust_mark_issuers_entity_confs
                # ]
                if not sc.validate_by_allowed_trust_marks():
                    raise InvalidRequiredTrustMark(
                        "The required Trust Marks are not valid"
                    )
                else:
                    self.verified_trust_marks.extend(sc.verified_trust_marks)

    def serialize(self):
        res = []
        # we have only the leaf's and TA's EC, all the intermediate EC will be dropped
        ta_ec: str = ""
        for stat in self.trust_path:
            if not isinstance(self.trust_anchor, str):
                if self.subject == stat.sub == stat.iss:
                    res.append(stat.jwt)
                    continue
                elif self.trust_anchor.sub == stat.sub == stat.iss:
                    ta_ec = stat.jwt
                    continue

            if stat.verified_descendant_statements:
                res.extend(
                    # [dict(i) for i in stat.verified_descendant_statements.values()]
                    [i for i in stat.verified_descendant_statements_as_jwt.values()]
                )
        if ta_ec:
            res.append(ta_ec)
        return res

    def start(self):
        try:
            self.get_trust_anchor_configuration()
            self.get_subject_configuration()
            self.discovery()
        except Exception as e:
            self.is_valid = False
            logger.error(f"{e}")
            raise e


# TODO: save trust chain in the plugin storage
# TRUST_CHAINS = {
#     "http://cie-provider.org:8002/oidc/op": TrustChain(
#         sub="http://cie-provider.org:8002/oidc/op",
#         trust_anchor=OIDCFED_DEFAULT_TRUST_ANCHOR,
#         exp=datetime(2022, 1, 1),
#         # iat=iat_now(),
#         jwks=[
#             {
#                 "kty": "RSA",
#                 "e": "AQAB",
#                 "n": "tg3aE9fd6ltXzNrim_4CGKYWfC3nqc_tv4Xjaw473CcrfiqDzeTKHfRfbvbqb1DwmI4fvCOi51EVcmKLnThzXynAUpyUvswvL8_uzgDWO1RSmBG1L0RE-CkKih4keXh1ku9hNs1_V-82dK5oLOR-VJLnhZCqThR4HH6TqLjjWrrXfsHVRvauJilX6FxGb5JFoc27VxxdH2c6P2SHC9wuB8tnfG7OSrSD1g2h7lTXbIfm78a0op67d_jupzkoKoCTmzkR2zvwTVVDd99vkDLY2WXmb8hIwG6dQZXYlkhqAYKzTuTZ0tjVh0OrqfDxYtLH3wQzzaJORewZYqLyB09P8w",
#                 "kid": "ZhSoaOedVOsBw6m2vclwSWiqqnGeOStT-gUclot_67w",
#             }
#         ],
#         metadata={
#             "federation_entity": {
#                 "federation_resolve_endpoint": "http://cie-provider.org:8002/oidc/op/resolve",
#                 "organization_name": "CIE OIDC identity provider",
#                 "homepage_uri": "http://cie-provider.org:8002",
#                 "policy_uri": "http://cie-provider.org:8002/oidc/op/en/website/legal-information",
#                 "logo_uri": "http://cie-provider.org:8002/static/svg/logo-cie.svg",
#                 "contacts": ["tech@example.it"],
#             },
#             "openid_provider": {
#                 "authorization_endpoint": "http://cie-provider.org:8002/oidc/op/authorization",
#                 "revocation_endpoint": "http://cie-provider.org:8002/oidc/op/revocation",
#                 "id_token_encryption_alg_values_supported": ["RSA-OAEP"],
#                 "id_token_encryption_enc_values_supported": ["A128CBC-HS256"],
#                 "token_endpoint": "http://cie-provider.org:8002/oidc/op/token",
#                 "userinfo_endpoint": "http://cie-provider.org:8002/oidc/op/userinfo",
#                 "introspection_endpoint": "http://cie-provider.org:8002/oidc/op/introspection",
#                 "claims_parameter_supported": True,
#                 "contacts": ["ops@https://idp.it"],
#                 "code_challenge_methods_supported": ["S256"],
#                 "client_registration_types_supported": ["automatic"],
#                 "request_authentication_methods_supported": {"ar": ["request_object"]},
#                 "acr_values_supported": [
#                     "https://www.spid.gov.it/SpidL1",
#                     "https://www.spid.gov.it/SpidL2",
#                     "https://www.spid.gov.it/SpidL3",
#                 ],
#                 "claims_supported": [
#                     "given_name",
#                     "family_name",
#                     "birthdate",
#                     "gender",
#                     "phone_number",
#                     "https://attributes.eid.gov.it/fiscal_number",
#                     "phone_number_verified",
#                     "email",
#                     "address",
#                     "document_details",
#                     "https://attributes.eid.gov.it/physical_phone_number",
#                 ],
#                 "grant_types_supported": ["authorization_code", "refresh_token"],
#                 "id_token_signing_alg_values_supported": ["RS256", "ES256"],
#                 "issuer": "http://cie-provider.org:8002/oidc/op",
#                 "jwks_uri": "http://cie-provider.org:8002/oidc/op/openid_provider/jwks.json",
#                 "signed_jwks_uri": "http://cie-provider.org:8002/oidc/op/openid_provider/jwks.jose",
#                 "jwks": {
#                     "keys": [
#                         {
#                             "kty": "RSA",
#                             "use": "sig",
#                             "e": "AQAB",
#                             "n": "rJoSYv1stwlbM11tR9SYGIJuzqlJe2bv2N35oPRbwV_epjNWvGG2ZqEj53YFMC8AMZNFhuLa_LNwr1kLVE-jXQe8xjiLhe7DgMf1OnSzq9yAEXVo19BPBwkgJe2jp9HIgM_nfbIsUbSSkFAM2CKvGb0Bk2GvvqXZ12P-fpbVyA9hIQr6rNTqnCGx2-v4oViGG4u_3iTw7D1ZvLWmrmZOaKnDAqG3MJSdQ-2ggQ-Aiahg48si9C9D_JgnBV9tJ2eCS58ZC6kVG5sftElQVdH6e26mz464TZj5QgCwZCTsAQfIvBoXSdCKxpnvsFfrajz4q9BiXAryxIOl5fLmCFVNhw",
#                             "kid": "Pd2N9-TZz_AWS3GFCkoYdRaXXls8YPhx_d_Ez7JwjQI",
#                         }
#                     ]
#                 },
#                 "scopes_supported": ["openid", "offline_access"],
#                 "logo_uri": "http://cie-provider.org:8002/static/images/logo-cie.png",
#                 "organization_name": "SPID OIDC identity provider",
#                 "op_policy_uri": "http://cie-provider.org:8002/oidc/op/en/website/legal-information",
#                 "request_parameter_supported": True,
#                 "request_uri_parameter_supported": True,
#                 "require_request_uri_registration": True,
#                 "response_types_supported": ["code"],
#                 "response_modes_supported": ["query", "form_post"],
#                 "subject_types_supported": ["pairwise", "public"],
#                 "token_endpoint_auth_methods_supported": ["private_key_jwt"],
#                 "token_endpoint_auth_signing_alg_values_supported": [
#                     "RS256",
#                     "RS384",
#                     "RS512",
#                     "ES256",
#                     "ES384",
#                     "ES512",
#                 ],
#                 "userinfo_encryption_alg_values_supported": [
#                     "RSA-OAEP",
#                     "RSA-OAEP-256",
#                 ],
#                 "userinfo_encryption_enc_values_supported": [
#                     "A128CBC-HS256",
#                     "A192CBC-HS384",
#                     "A256CBC-HS512",
#                     "A128GCM",
#                     "A192GCM",
#                     "A256GCM",
#                 ],
#                 "userinfo_signing_alg_values_supported": [
#                     "RS256",
#                     "RS384",
#                     "RS512",
#                     "ES256",
#                     "ES384",
#                     "ES512",
#                 ],
#                 "request_object_encryption_alg_values_supported": [
#                     "RSA-OAEP",
#                     "RSA-OAEP-256",
#                 ],
#                 "request_object_encryption_enc_values_supported": [
#                     "A128CBC-HS256",
#                     "A192CBC-HS384",
#                     "A256CBC-HS512",
#                     "A128GCM",
#                     "A192GCM",
#                     "A256GCM",
#                 ],
#                 "request_object_signing_alg_values_supported": [
#                     "RS256",
#                     "RS384",
#                     "RS512",
#                     "ES256",
#                     "ES384",
#                     "ES512",
#                 ],
#             },
#         },
#         parties_involved=[
#             "http://cie-provider.org:8002/oidc/op",
#             "http://trust-anchor.org:8000",
#         ],
#         status="valid",
#         chain=[
#             "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiWmhTb2FPZWRWT3NCdzZtMnZjbHdTV2lxcW5HZU9TdFQtZ1VjbG90XzY3dyJ9.eyJleHAiOjE3MDg3NTYyOTYsImlhdCI6MTcwODU4MzQ5NiwiaXNzIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wIiwic3ViIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiJ0ZzNhRTlmZDZsdFh6TnJpbV80Q0dLWVdmQzNucWNfdHY0WGphdzQ3M0NjcmZpcUR6ZVRLSGZSZmJ2YnFiMUR3bUk0ZnZDT2k1MUVWY21LTG5UaHpYeW5BVXB5VXZzd3ZMOF91emdEV08xUlNtQkcxTDBSRS1Da0tpaDRrZVhoMWt1OWhOczFfVi04MmRLNW9MT1ItVkpMbmhaQ3FUaFI0SEg2VHFMampXcnJYZnNIVlJ2YXVKaWxYNkZ4R2I1SkZvYzI3Vnh4ZEgyYzZQMlNIQzl3dUI4dG5mRzdPU3JTRDFnMmg3bFRYYklmbTc4YTBvcDY3ZF9qdXB6a29Lb0NUbXprUjJ6dndUVlZEZDk5dmtETFkyV1htYjhoSXdHNmRRWlhZbGtocUFZS3pUdVRaMHRqVmgwT3JxZkR4WXRMSDN3UXp6YUpPUmV3WllxTHlCMDlQOHciLCJraWQiOiJaaFNvYU9lZFZPc0J3Nm0ydmNsd1NXaXFxbkdlT1N0VC1nVWNsb3RfNjd3In1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL3Jlc29sdmUiLCJvcmdhbml6YXRpb25fbmFtZSI6IkNJRSBPSURDIGlkZW50aXR5IHByb3ZpZGVyIiwiaG9tZXBhZ2VfdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMiIsInBvbGljeV91cmkiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvZW4vd2Vic2l0ZS9sZWdhbC1pbmZvcm1hdGlvbiIsImxvZ29fdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9zdGF0aWMvc3ZnL2xvZ28tY2llLnN2ZyIsImNvbnRhY3RzIjpbInRlY2hAZXhhbXBsZS5pdCJdfSwib3BlbmlkX3Byb3ZpZGVyIjp7ImF1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvYXV0aG9yaXphdGlvbiIsInJldm9jYXRpb25fZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvcmV2b2NhdGlvbiIsImlkX3Rva2VuX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlNBLU9BRVAiXSwiaWRfdG9rZW5fZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4Q0JDLUhTMjU2Il0sInRva2VuX2VuZHBvaW50IjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL3Rva2VuIiwidXNlcmluZm9fZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvdXNlcmluZm8iLCJpbnRyb3NwZWN0aW9uX2VuZHBvaW50IjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL2ludHJvc3BlY3Rpb24iLCJjbGFpbXNfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwiY29udGFjdHMiOlsib3BzQGh0dHBzOi8vaWRwLml0Il0sImNvZGVfY2hhbGxlbmdlX21ldGhvZHNfc3VwcG9ydGVkIjpbIlMyNTYiXSwiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlc19zdXBwb3J0ZWQiOlsiYXV0b21hdGljIl0sInJlcXVlc3RfYXV0aGVudGljYXRpb25fbWV0aG9kc19zdXBwb3J0ZWQiOnsiYXIiOlsicmVxdWVzdF9vYmplY3QiXX0sImFjcl92YWx1ZXNfc3VwcG9ydGVkIjpbImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMSIsImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMiIsImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMyJdLCJjbGFpbXNfc3VwcG9ydGVkIjpbImdpdmVuX25hbWUiLCJmYW1pbHlfbmFtZSIsImJpcnRoZGF0ZSIsImdlbmRlciIsInBob25lX251bWJlciIsImh0dHBzOi8vYXR0cmlidXRlcy5laWQuZ292Lml0L2Zpc2NhbF9udW1iZXIiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiLCJlbWFpbCIsImFkZHJlc3MiLCJkb2N1bWVudF9kZXRhaWxzIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLmVpZC5nb3YuaXQvcGh5c2ljYWxfcGhvbmVfbnVtYmVyIl0sImdyYW50X3R5cGVzX3N1cHBvcnRlZCI6WyJhdXRob3JpemF0aW9uX2NvZGUiLCJyZWZyZXNoX3Rva2VuIl0sImlkX3Rva2VuX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJFUzI1NiJdLCJpc3N1ZXIiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AiLCJqd2tzX3VyaSI6Imh0dHA6Ly9jaWUtcHJvdmlkZXIub3JnOjgwMDIvb2lkYy9vcC9vcGVuaWRfcHJvdmlkZXIvandrcy5qc29uIiwic2lnbmVkX2p3a3NfdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL29wZW5pZF9wcm92aWRlci9qd2tzLmpvc2UiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsInVzZSI6InNpZyIsImUiOiJBUUFCIiwibiI6InJKb1NZdjFzdHdsYk0xMXRSOVNZR0lKdXpxbEplMmJ2Mk4zNW9QUmJ3Vl9lcGpOV3ZHRzJacUVqNTNZRk1DOEFNWk5GaHVMYV9MTndyMWtMVkUtalhRZTh4amlMaGU3RGdNZjFPblN6cTl5QUVYVm8xOUJQQndrZ0plMmpwOUhJZ01fbmZiSXNVYlNTa0ZBTTJDS3ZHYjBCazJHdnZxWFoxMlAtZnBiVnlBOWhJUXI2ck5UcW5DR3gyLXY0b1ZpR0c0dV8zaVR3N0QxWnZMV21ybVpPYUtuREFxRzNNSlNkUS0yZ2dRLUFpYWhnNDhzaTlDOURfSmduQlY5dEoyZUNTNThaQzZrVkc1c2Z0RWxRVmRINmUyNm16NDY0VFpqNVFnQ3daQ1RzQVFmSXZCb1hTZENLeHBudnNGZnJhano0cTlCaVhBcnl4SU9sNWZMbUNGVk5odyIsImtpZCI6IlBkMk45LVRael9BV1MzR0ZDa29ZZFJhWFhsczhZUGh4X2RfRXo3SndqUUkifV19LCJzY29wZXNfc3VwcG9ydGVkIjpbIm9wZW5pZCIsIm9mZmxpbmVfYWNjZXNzIl0sImxvZ29fdXJpIjoiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9zdGF0aWMvaW1hZ2VzL2xvZ28tY2llLnBuZyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiU1BJRCBPSURDIGlkZW50aXR5IHByb3ZpZGVyIiwib3BfcG9saWN5X3VyaSI6Imh0dHA6Ly9jaWUtcHJvdmlkZXIub3JnOjgwMDIvb2lkYy9vcC9lbi93ZWJzaXRlL2xlZ2FsLWluZm9ybWF0aW9uIiwicmVxdWVzdF9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1ZXN0X3VyaV9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1aXJlX3JlcXVlc3RfdXJpX3JlZ2lzdHJhdGlvbiI6dHJ1ZSwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbImNvZGUiXSwicmVzcG9uc2VfbW9kZXNfc3VwcG9ydGVkIjpbInF1ZXJ5IiwiZm9ybV9wb3N0Il0sInN1YmplY3RfdHlwZXNfc3VwcG9ydGVkIjpbInBhaXJ3aXNlIiwicHVibGljIl0sInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kc19zdXBwb3J0ZWQiOlsicHJpdmF0ZV9rZXlfand0Il0sInRva2VuX2VuZHBvaW50X2F1dGhfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXSwidXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUCIsIlJTQS1PQUVQLTI1NiJdLCJ1c2VyaW5mb19lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkIjpbIkExMjhDQkMtSFMyNTYiLCJBMTkyQ0JDLUhTMzg0IiwiQTI1NkNCQy1IUzUxMiIsIkExMjhHQ00iLCJBMTkyR0NNIiwiQTI1NkdDTSJdLCJ1c2VyaW5mb19zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2IiwiUlMzODQiLCJSUzUxMiIsIkVTMjU2IiwiRVMzODQiLCJFUzUxMiJdLCJyZXF1ZXN0X29iamVjdF9lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTQS1PQUVQIiwiUlNBLU9BRVAtMjU2Il0sInJlcXVlc3Rfb2JqZWN0X2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIl0sInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJSUzM4NCIsIlJTNTEyIiwiRVMyNTYiLCJFUzM4NCIsIkVTNTEyIl19fSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAiXX0.E7g5cjdwPaFidjdGulxrlTjPKqyLjJDRDN4ViL-2vy1QzxltXu8Sy-yqH_36XwoEl6_S1qipuquEePYrQthBLwXbos3vRlH0sl8-Bxq2AwtijmGfJHLmEmK5niEBVRedADoUhrifqi27JPMgTnv_DH2XWcDbUKg64aI-6xqONY8YXtC34biS7vjCTO6rrYOQJCHHStwKQ3U6JRPVH_UrGbCUShhrrCSwHwIsGzKr3y7LpMTv908r2GgqtnPuJ9xn-2veqCyeBEJBClsRtM8HOs30MPOqdgXk2WHeSe0c6iY0k65yxWC9gP_V2EzNZZtZQgFQwEb0YQ0K5i8U7fLqqA",
#             "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiQlh2ZnJsbmhBTXVIUjA3YWpVbUFjQlJRY1N6bXcwY19SQWdKbnBTLTlXUSJ9.eyJleHAiOjE3MDg1ODU0NzYsImlhdCI6MTcwODU4MzQ5NiwiaXNzIjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMCIsInN1YiI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6Im84SW9sUmpabGt6Y3QtNDhyaHJWbFRuWVUxcGtNYlZKRC1EVTA1b01TOVJWR3JzRnlwZzk4bS1LdzRINHFOUHlRVngyT1FPUmkteFNoZ2s3SFUtZ0tfMnBWZ3VZa3YwNkZhakxfZWRFQXFxc3F0Xzc0UWYyV0xSQzVwZkpHX3o5T1B6WThKR3lrLXozU2JlSE5fQlhLSThHWTVFNFdVMlNzdG1ROWZ5TDRDeHRSZmpVaWE4bGltVENfM01PcFQzemk1bnIwM2pmYmpwbmpnYTUxcVh1cnhubHpjM2FfeGprNVJBQXBLeFV2TndoSjI3NU0wQ21COTlEalB3RjZCTHZVZ0pxZ3lDcFVPbjM2TE9oSTRGcXVWcWhxaGl3S2xNbWlNZTN5eTB5TlE3RlhCV3hqemhleGJweWMzVnU3ekZJSFBBY0M0VXlJUWhjM3dhRWoydmlYdyIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JSUWNTem13MGNfUkFnSm5wUy05V1EifV19LCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJjb250YWN0cyI6WyJvcHNAbG9jYWxob3N0Il0sImZlZGVyYXRpb25fZmV0Y2hfZW5kcG9pbnQiOiJodHRwOi8vdHJ1c3QtYW5jaG9yLm9yZzo4MDAwL2ZldGNoIiwiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMC9yZXNvbHZlIiwiZmVkZXJhdGlvbl90cnVzdF9tYXJrX3N0YXR1c19lbmRwb2ludCI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvdHJ1c3RfbWFya19zdGF0dXMiLCJob21lcGFnZV91cmkiOiJodHRwOi8vdHJ1c3QtYW5jaG9yLm9yZzo4MDAwIiwib3JnYW5pemF0aW9uX25hbWUiOiJleGFtcGxlIFRBIiwicG9saWN5X3VyaSI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvZW4vd2Vic2l0ZS9sZWdhbC1pbmZvcm1hdGlvbiIsImxvZ29fdXJpIjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMC9zdGF0aWMvc3ZnL3NwaWQtbG9nby1jLWxiLnN2ZyIsImZlZGVyYXRpb25fbGlzdF9lbmRwb2ludCI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvbGlzdCJ9fSwidHJ1c3RfbWFya19pc3N1ZXJzIjp7Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHVibGljIjpbImh0dHBzOi8vcmVnaXN0cnkuc3BpZC5hZ2lkLmdvdi5pdCIsImh0dHBzOi8vcHVibGljLmludGVybWVkaWFyeS5zcGlkLml0Il0sImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHJpdmF0ZSI6WyJodHRwczovL3JlZ2lzdHJ5LnNwaWQuYWdpZC5nb3YuaXQiLCJodHRwczovL3ByaXZhdGUub3RoZXIuaW50ZXJtZWRpYXJ5Lml0Il0sImh0dHBzOi8vc2dkLmFhLml0L29uYm9hcmRpbmciOlsiaHR0cHM6Ly9zZ2QuYWEuaXQiXX0sImNvbnN0cmFpbnRzIjp7Im1heF9wYXRoX2xlbmd0aCI6MX19.TZM8mEg-f-Wm2MRc9EoUmBb_C-K1EJQM4NtYwiyb8buemzM5stS3sgqkDTvyBrnzd5JIzKO00CPoINX_8GxgDkOw7Y7YaOHl6ldqtGx_cIVycOnszHLnckVtpjOqit-ZvXGmpEYuM2dspoAs6Cnt1ftaWkJZm7v5BlOPviBNkzGdB2G7SOaVU99N_6QUCOc_4aieli-150ch5SjR1LtLmKpfBYrzMirLWJtB0Jay4ynS7PbGvIkNmwsGeNs21P_bFf9Zu63YJjLjAoX7e4ZTTnVhcgosLShxFPnfdu6strImkJghqn3I4wqDKCnVyMIeTqmX4h5kYPrCq0lWV09FOQ",
#         ],
#     ),
# }
