from ..config import OIDCFED_ACR_PROFILES
from ..config import RP_REQUEST_CLAIM_BY_PROFILE
from ..config import RP_REQUEST_EXP
from ..exceptions import InvalidTrustchain
from ..jwtse import create_jws
from ..jwtse import unpad_jwt_payload
from ..jwtse import verify_at_hash
from ..jwtse import verify_jws
from ..utils import get_jwk_from_jwt
from ..utils import get_jwks
from ..utils import get_pkce
from .rp import OAuth2AuthorizationCodeGrant
from .rp import OidcRPView
from .rp import OidcUserInfo
from copy import deepcopy
from datetime import datetime
from oic import rndstr
from oic.oic.message import EndSessionRequest
from pas.plugins.oidc import _
from pas.plugins.oidc import logger
from pas.plugins.oidc import utils
from pas.plugins.oidc.plugins import OAuth2ConnectionException
from pas.plugins.oidc.session import Session
from plone import api
from Products.Five.browser import BrowserView
from urllib.parse import quote
from urllib.parse import urlencode
from zExceptions import NotFound

import json
import uuid


# from zExceptions import Unauthorized


class RequireLoginView(BrowserView):
    """Our version of the require-login view from Plone.

    Our challenge plugin redirects here.
    Note that the plugin has no way of knowing if you are authenticated:
    its code is called before this is known.
    I think.
    """

    def __call__(self):
        if api.user.is_anonymous():
            # context is our PAS plugin
            base_url = self.context.absolute_url()
            url = f"{base_url}/login"
            came_from = self.request.get("came_from", None)
            if came_from:
                url = f"{url}?came_from={quote(came_from)}"
        else:
            url = api.portal.get().absolute_url()
            url = f"{url}/insufficient-privileges"

        self.request.response.redirect(url)


class LoginView(OidcRPView):
    def _internal_redirect_location(self, session: Session) -> str:
        came_from = session.get("came_from")
        portal_url = api.portal.get_tool("portal_url")
        if not (came_from and portal_url.isURLInPortal(came_from)):
            came_from = api.portal.get().absolute_url()
        return came_from

    def __call__(self):
        """
        Redirects to the OIDC provider login page.

        For OICD Federation, the provider is specified in the provider query parameter.

            http://localhost:8080/Plone/acl_users/oidc/login?provider=http://trust-anchor.org:8000/oidc/op&profile=spid
            http://localhost:8080/Plone/acl_users/oidc/login?provider=http://cie-provider.org:8002/oidc/op&profile=cie
        """
        # if oidc federation is enabled, we need to check the trust chain
        try:
            tc = self.get_oidc_op()
            if not tc:
                context = {
                    "error": "request rejected",
                    "error_description": "Trust Chain is unavailable.",
                }
                self.request.response.setStatus(400)
                return self.error_page(**context)
        except InvalidTrustchain as exc:
            context = {
                "error": "request rejected",
                "error_description": str(exc.args),
            }
            self.request.response.setStatus(400)
            return self.error_page(**context)
        except Exception as exc:
            context = {
                "error": "request rejected",
                "error_description": _(str(exc.args)),
            }
            logger.exception("request_rejected")
            self.request.response.setStatus(500)
            return self.error_page(**context)

        provider_metadata = tc.metadata.get("openid_provider", None)
        if not provider_metadata:
            context = {
                "error": "request rejected",
                "error_description": _("provider metadata not found"),
            }
            self.request.response.setStatus(400)
            return self.error_page(**context)

        # TODO: RPs multitenancy?
        # entity_conf = self.pas.get_federation_configuration()
        # # FederationEntityConfiguration.objects.filter(
        # #     entity_type="openid_relying_party",
        # #     # TODO: RPs multitenancy?
        # #     # sub = request.build_absolute_uri()
        # # ).first()
        # if not entity_conf:
        #     context = {
        #         "error": "request rejected",
        #         "error_description": _("Missing configuration."),
        #     }
        #     self.request.response.setStatus(400)
        #     return self.error_page(**context)
        # client_conf = entity_conf["metadata"]["openid_relying_party"]
        if not (
            provider_metadata.get("jwks_uri", None)
            or provider_metadata.get("jwks", None)
        ):
            context = {
                "error": "request rejected",
                "error_description": _("Invalid provider Metadata."),
            }
            self.request.response.setStatus(400)
            return self.error_page(**context)

        # TODO
        # jwks_dict = get_jwks(provider_metadata, federation_jwks=tc.jwks)

        authz_endpoint = provider_metadata["authorization_endpoint"]
        # TODO: use format_redirect_uri (?)
        redirect_uri = self.request.get("redirect_uri", self.pas.redirect_uris[0])
        if redirect_uri not in self.pas.redirect_uris:
            logger.warning(
                f"Requested for unknown redirect uri {redirect_uri}. "
                f"Reverted to default {self.pas.redirect_uris[0]}."
            )
            redirect_uri = self.pas.redirect_uris[0]
        _profile = self.request.get("profile", "spid")
        _timestamp_now = int(datetime.now().timestamp())
        authz_data = dict(
            iss=self.pas.get_subject(),
            scope=self.request.get("scope", None) or "openid",
            redirect_uri=redirect_uri,
            response_type=self.pas.response_types[0],
            nonce=rndstr(32),
            state=rndstr(32),
            client_id=self.pas.get_subject(),
            endpoint=authz_endpoint,
            acr_values=OIDCFED_ACR_PROFILES,
            iat=_timestamp_now,
            exp=_timestamp_now + RP_REQUEST_EXP,
            jti=str(uuid.uuid4()),
            aud=[tc.sub, authz_endpoint],
            claims=RP_REQUEST_CLAIM_BY_PROFILE[_profile],
        )

        _prompt = self.request.get("prompt", "consent login")

        # if "offline_access" in authz_data["scope"]:
        # _prompt.extend(["consent login"])

        authz_data["prompt"] = _prompt

        # PKCE
        # pkce_func = import_string(RP_PKCE_CONF["function"])
        # pkce_values = pkce_func(**RP_PKCE_CONF["kwargs"])
        pkce_values = get_pkce(code_challenge_length=64, code_challenge_method="S256")

        authz_data.update(pkce_values)
        #
        authz_entry = dict(
            client_id=self.pas.get_subject(),
            state=authz_data["state"],
            endpoint=authz_endpoint,
            # TODO: better have here an organization name
            provider_id=tc.sub,
            data=json.dumps(authz_data),
            provider_configuration=provider_metadata,
            came_from=self.request.get("came_from"),
        )

        # save session server side or client side ?
        # Flow start
        # TODO: valutare/verificare la gestione del came_from
        # came_from = self.request.get("came_from")
        # if came_from:
        #     session.set("came_from", came_from)

        # TODO: Prune the old or unbounded authz ...
        # OidcAuthentication.objects.create(**authz_entry)
        use_session_data_manager: bool = self.context.getProperty(
            "use_session_data_manager"
        )
        # use_pkce: bool = self.context.getProperty("use_pkce")
        # import pdb; pdb.set_trace()
        session = Session(self.request, use_session_data_manager)
        session.set(authz_data["state"], authz_entry)
        # state is used to keep track of responses to outstanding requests (state).
        # nonce is a string value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        # session.set("authz", authz_entry)
        # session.set("state", authz_entry["state"])
        # session.set("client_id", authz_entry["client_id"])
        # session.set("data", authz_entry["data"])
        # session.set("nonce", rndstr())
        # if use_pkce:
        #     session.set("verifier", rndstr(128))

        #
        # class OidcAuthentication(models.Model):
        #     client_id = models.CharField(max_length=255)
        #     state = models.CharField(max_length=255, unique=True, default=uuid.uuid4)
        #     endpoint = models.URLField(blank=True, null=True)
        #     data = models.TextField(blank=True, null=True)
        #     successful = models.BooleanField(default=False)
        #
        #     provider_id = models.CharField(max_length=255, blank=True, null=True)
        #     provider_configuration = models.JSONField(
        #         blank=True, null=True, default=dict
        #     )
        #
        #     created = models.DateTimeField(auto_now_add=True)
        #     modified = models.DateTimeField(auto_now=True)
        #
        #     class Meta:
        #         verbose_name = "OIDC Authentication"
        #         verbose_name_plural = "OIDC Authentications"
        #
        #     def __str__(self):
        #         return f"{self.client_id} {self.state} to {self.endpoint}"

        authz_data.pop("code_verifier")
        # add the signed request object
        authz_data_obj = deepcopy(authz_data)
        authz_data_obj["iss"] = self.pas.get_subject()

        # sub claim MUST not be used to prevent that this jwt
        # could be reused as a private_key_jwt
        # authz_data_obj["sub"] = client_conf["client_id"]

        request_obj = create_jws(authz_data_obj, self.pas.get_private_jwks_core()[0])
        authz_data["request"] = request_obj
        uri_path = urlencode(
            {
                "client_id": authz_data["client_id"],
                "scope": authz_data["scope"],
                "response_type": authz_data["response_type"],
                "code_challenge": authz_data["code_challenge"],
                "code_challenge_method": authz_data["code_challenge_method"],
                "request": authz_data["request"],
            }
        )
        if "?" in authz_endpoint:
            qstring = "&"
        else:
            qstring = "?"
        url = qstring.join((authz_endpoint, uri_path))
        logger.info(f"Starting Authz request to {url}")

        self.request.response.redirect(url)
        return

        # ---- PLAIN OIDC as pas.plugins.oidc ----
        #
        # session = utils.initialize_session(self.context, self.request)
        # args = utils.authorization_flow_args(self.context, session)
        # error_msg = ""
        # try:
        #     client = self.context.get_oauth2_client()
        # except OAuth2ConnectionException:
        #     client = None
        #     error_msg = _("There was an error getting the oauth2 client.")
        # if client:
        #     try:
        #         auth_req = client.construct_AuthorizationRequest(request_args=args)
        #         login_url = auth_req.request(client.authorization_endpoint)
        #     except Exception as e:
        #         logger.error(e)
        #         error_msg = _(
        #             "There was an error during the login process. Please try again."
        #         )
        #     else:
        #         self.request.response.setHeader(
        #             "Cache-Control", "no-cache, must-revalidate"
        #         )
        #         self.request.response.redirect(login_url)
        #
        # if error_msg:
        #     api.portal.show_message(error_msg)
        #     redirect_location = self._internal_redirect_location(session)
        #     self.request.response.redirect(redirect_location)
        # return


class LogoutView(BrowserView):
    def __call__(self):
        try:
            client = self.context.get_oauth2_client()
        except OAuth2ConnectionException:
            return ""

        # session = Session(
        #   self.request,
        #   use_session_data_manager=self.context.getProperty("use_session_data_manager")
        # )
        # state is used to keep track of responses to outstanding requests (state).
        # https://github.com/keycloak/keycloak-documentation/blob/master/securing_apps/topics/oidc/java/logout.adoc
        # session.set('end_session_state', rndstr())

        redirect_uri = utils.url_cleanup(api.portal.get().absolute_url())

        if self.context.getProperty("use_deprecated_redirect_uri_for_logout"):
            args = {
                "redirect_uri": redirect_uri,
            }
        else:
            args = {
                "post_logout_redirect_uri": redirect_uri,
                "client_id": self.context.getProperty("client_id"),
            }

        pas = api.portal.get_tool("acl_users")
        auth_cookie_name = pas.credentials_cookie_auth.cookie_name

        # end_req = client.construct_EndSessionRequest(request_args=args)
        end_req = EndSessionRequest(**args)
        logout_url = end_req.request(client.end_session_endpoint)
        self.request.response.setHeader("Cache-Control", "no-cache, must-revalidate")
        # TODO: change path with portal_path
        self.request.response.expireCookie(auth_cookie_name, path="/")
        self.request.response.expireCookie("auth_token", path="/")
        self.request.response.redirect(logout_url)
        return


class CallbackView(OidcRPView, OAuth2AuthorizationCodeGrant, OidcUserInfo):
    """
    View which processes an Authorization Response
    https://tools.ietf.org/html/rfc6749#section-4.1.2

    eg:
    /redirect_uri?code=tYkP854StRqBVcW4Kg4sQfEN5Qz&state=R9EVqaazGsj3wg5JgxIgm8e8U4BMvf7W
    """

    # TODO
    # def user_reunification(self, user_attrs: dict):
    #     user_model = get_user_model()

    #     if user_attrs.get(RP_USER_LOOKUP_FIELD, None):
    #         lookup = {
    #             f"attributes__{RP_USER_LOOKUP_FIELD}": user_attrs.get(RP_USER_LOOKUP_FIELD)
    #         }
    #     else:
    #         logger.warning("User attribute not found for reunification, try sub")
    #         lookup = {
    #             "username": user_attrs["username"]
    #         }
    #     user = user_model.objects.filter(**lookup).first()
    #     if user:
    #         user.attributes.update(user_attrs)
    #         user.save()
    #         logger.info(f"{RP_USER_LOOKUP_FIELD} matched on user {user}")
    #         return user
    #     elif RP_USER_CREATE:
    #         user = user_model.objects.create(
    #             username=user_attrs.get("username", user_attrs["sub"]),
    #             first_name=user_attrs.get("given_name", user_attrs["sub"]),
    #             last_name=user_attrs.get("family_name", user_attrs["sub"]),
    #             email=user_attrs.get("email", ""),
    #             attributes=user_attrs,
    #         )
    #         logger.info(f"Created new user {user}")
    #         return user

    def __call__(self):
        """
        The Authorization callback, the redirect uri where the auth code lands
        """

        # error_template = "rp_error.html"
        if "error" in self.request:
            # TODO: handle error status 401
            raise NotImplementedError(
                "Error handling not implemented yet", self.request.get("error")
            )

        # {'code': 'c35dce7965cb5...',
        #  'state': 'Q9wkbVdhnq2DZG7yxouoUEU8oN1GLmIs',
        #  'iss': 'http://cie-provider.org:8002/oidc/op'}

        # search session server side
        # authz = OidcAuthentication.objects.filter(
        #     state=request_args.get("state"),
        # )

        # TODO: search session server side
        # authz = utils.load_existing_session(self.context, self.request)
        session = Session(self.request, use_session_data_manager=False)
        authz = session.get(self.request.get("state"))

        # request_args = {k: v for k, v in request.GET.items()}
        # try:
        #     self.validate_json_schema(
        #         request.GET.dict(),
        #         "authn_response",
        #         "Authn response object validation failed"
        #     )
        # except ValidationException:
        #     return JsonResponse(
        #         {
        #             "error": "invalid_request",
        #             "error_description": "Authn response object validation failed",
        #         },
        #         status = 400
        #     )

        if not authz:
            # TODO: handle error status 401
            error = {
                "error": "unauthorized request",
                "error_description": _("Authentication not found"),
            }
            raise NotFound(self.context, error)
            # return render(request, self.error_template, context, status=401)
        # else:
        #     authz = authz.last()
        # authz = authz.get("authz")

        code = self.request.get("code")
        # TODO: validate iss
        # # mixups attacks prevention
        # if request.GET.get('iss', None):
        #     if request.GET['iss'] != authz.provider_id:
        #         context = {
        #             "error": "invalid request",
        #             "error_description": _(
        #                 "authn response validation failed: mixups attack prevention."
        #             ),
        #         }
        #         return render(request, self.error_template, context, status=400)

        # authz_token = OidcAuthenticationToken.objects.create(
        #     authz_request=authz, code=code
        # )

        # TODO: cercare la configurazione del client in base al client_id dell'authz
        # XXX: questo anzichè nella call andrebbe nella init ? della vista o del plugin ?
        # self.rp_conf = authz["client_id"]
        # self.rp_conf = self.pas.get_federation_configuration()
        # self.rp_conf = FederationEntityConfiguration.objects.filter(
        #     sub=authz_token.authz_request.client_id
        # ).first()
        # if not self.rp_conf:
        #     context = {
        #         "error": "invalid request",
        #         "error_description": _("Relying party not found"),
        #     }
        #     return render(request, self.error_template, context, status=400)

        authz_data = json.loads(authz.get("data"))

        token_response = self.access_token_request(
            redirect_uri=authz_data["redirect_uri"],
            state=authz.get("state"),
            code=code,
            issuer_id=authz.get("provider_id"),
            # client_conf=self.rp_conf,
            token_endpoint_url=authz.get("provider_configuration")["token_endpoint"],
            audience=[authz.get("provider_id")],
            code_verifier=authz_data.get("code_verifier"),
        )
        if not token_response:
            context = {
                "error": "invalid token response",
                "error_description": _("Token response seems not to be valid"),
            }
            # TODO: handle error status 400
            raise NotFound(self.context, context)
            # return render(request, self.error_template, context, status=400)

        else:
            # TODO
            # try:
            #     self.validate_json_schema(
            #         token_response,
            #         "token_response",
            #         "Token response object validation failed"
            #     )
            # except ValidationException:
            #     return JsonResponse(
            #         {
            #             "error": "invalid_request",
            #             "error_description": "Token response object validation failed",
            #         },
            #         status = 400
            #     )
            pass
        jwks = get_jwks(authz["provider_configuration"])
        access_token = token_response["access_token"]
        id_token = token_response["id_token"]

        op_ac_jwk = get_jwk_from_jwt(access_token, jwks)
        op_id_jwk = get_jwk_from_jwt(id_token, jwks)

        if not op_ac_jwk or not op_id_jwk:
            logger.warning(
                "Token signature validation error, "
                f"the tokens were signed with a different kid from: {jwks}."
            )
            context = {
                "error": "invalid_token",
                "error_description": _("Authentication token seems not to be valid."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        try:
            verify_jws(access_token, op_ac_jwk)
        except Exception as e:
            logger.warning(f"Access Token signature validation error: {e} ")
            context = {
                "error": "token verification failed",
                "error_description": _("Authentication token validation error."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        try:
            verify_jws(id_token, op_id_jwk)
        except Exception as e:
            logger.warning(f"ID Token signature validation error: {e} ")
            context = {
                "error": "token verification failed",
                "error_description": _("ID token validation error."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        decoded_id_token = unpad_jwt_payload(id_token)
        # logger.debug(decoded_id_token)

        try:
            verify_at_hash(decoded_id_token, access_token)
        except Exception as e:
            logger.warning(f"at_hash validation error: {e} ")
            context = {
                "error": "at_hash verification failed",
                "error_description": _("at_hash validation error."),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=403)

        # decoded_access_token = unpad_jwt_payload(access_token)
        # logger.debug(decoded_access_token)

        # authz_token.access_token = access_token
        # authz_token.id_token = id_token
        # authz_token.scope = token_response.get("scope")
        # authz_token.token_type = token_response["token_type"]
        # authz_token.expires_in = token_response["expires_in"]
        # authz_token.save()

        user_info = self.get_userinfo(
            authz["state"],
            access_token,
            authz["provider_configuration"],
            verify=False,  # TODO
            # verify=HTTPC_PARAMS.get("connection", {}).get("ssl", True)
        )
        if not user_info:
            logger.warning(
                "Userinfo request failed for state: "
                f"{authz['state']} to {authz['provider_id']}"
            )
            context = {
                "error": "invalid userinfo response",
                "error_description": _("UserInfo response seems not to be valid"),
            }
            # TODO
            raise Exception(context)
            # return render(request, self.error_template, context, status=400)

        # # here django user attr mapping
        # user_attrs = process_user_attributes(userinfo, RP_ATTR_MAP, authz.__dict__)
        # if not user_attrs:
        #     _msg = "No user attributes have been processed"
        #     logger.warning(f"{_msg}: {userinfo}")
        #     # TODO: verify error message and status
        #     context = {
        #         "error": "missing user attributes",
        #         "error_description": _(f"{_msg}: {userinfo}"),
        #     }
        #     return render(request, self.error_template, context, status=403)

        # user = self.user_reunification(user_attrs)
        # if not user:
        #     # TODO: verify error message and status
        #     context = {"error": _("No user found"), "error_description": _("")}
        #     return render(request, self.error_template, context, status=403)

        # request.session["rt_expiration"] = 0

        # if token_response.get('refresh_token', None):
        #     refresh_token = token_response["refresh_token"]
        #     authz_token.refresh_token = refresh_token
        #     decoded_refresh_token = unpad_jwt_payload(refresh_token)
        #     request.session["rt_expiration"] = decoded_refresh_token['exp'] - iat_now()
        #     request.session["rt_jti"] = decoded_refresh_token['jti']
        #     logger.info(decoded_refresh_token)

        # # authenticate the user
        # login(request, user)
        # request.session["oidc_rp_user_attrs"] = user_attrs

        # request.session["at_expiration"] = decoded_access_token['exp'] - iat_now()
        # request.session["at_jti"] = decoded_access_token['jti']

        # authz_token.user = user
        # authz_token.save()
        # return HttpResponseRedirect(
        #     getattr(
        #         settings, "LOGIN_REDIRECT_URL", None
        #     ) or reverse("spid_cie_rp_echo_attributes")
        # )

        self.context.rememberIdentity(user_info)
        self.request.response.setHeader("Cache-Control", "no-cache, must-revalidate")
        return_url = utils.process_came_from(
            self.request.get("came_from", authz.get("came_from"))
        )
        self.request.response.redirect(return_url)
        return

        # --- plain oidc as pas.plugins.oidc ---

        # session = utils.load_existing_session(self.context, self.request)
        # client = self.context.get_oauth2_client()
        # qs = self.request.environ["QUERY_STRING"]
        # args, state = utils.parse_authorization_response(
        #     self.context, qs, client, session
        # )
        # if self.context.getProperty("use_modified_openid_schema"):
        #     IdToken.c_param.update(
        #         {
        #             "email_verified": utils.SINGLE_OPTIONAL_BOOLEAN_AS_STRING,
        #             "phone_number_verified": utils.SINGLE_OPTIONAL_BOOLEAN_AS_STRING,
        #         }
        #     )
        #
        # # The response you get back is an instance of an AccessTokenResponse
        # # or again possibly an ErrorResponse instance.
        # user_info = utils.get_user_info(client, state, args)
        # if user_info:
        #     self.context.rememberIdentity(user_info)
        #     self.request.response.setHeader(
        #         "Cache-Control", "no-cache, must-revalidate"
        #     )
        #     return_url = utils.process_came_from(session, self.request.get("came_from"))
        #     self.request.response.redirect(return_url)
        # else:
        #     raise Unauthorized()
