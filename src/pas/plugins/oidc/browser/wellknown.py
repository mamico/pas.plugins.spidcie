# TODO: pub deve essere costruita direttamente dalal configurazione del replaying party
# pub = get_federation_entity()
# conf = FEDERATION_CONFIGURATIONS[0]
from ..config import FEDERATION_CONFIGURATIONS
from ..jwtse import create_jws
from .openidfedaration import get_federation_entity
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

    def publishTraverse(self, request, name: str):
        if self.name is None:
            self.name = name
        return self

    def __call__(self):
        if self.name == "openid-federation":
            pub = get_federation_entity()
            conf = FEDERATION_CONFIGURATIONS[0]
            if self.request.get("format") == "json":  # pragma: no cover
                self.request.response.setHeader("Content-Type", "application/json")
                return json.dumps(pub)
            else:
                self.request.response.setHeader(
                    "Content-Type", "application/entity-statement+jwt"
                )
                return create_jws(
                    pub,
                    conf["jwks_fed"][0],
                    alg=conf["default_signature_alg"],
                    typ="entity-statement+jwt",
                )
        else:
            raise NotFound(self.request, self.name, self.context)
