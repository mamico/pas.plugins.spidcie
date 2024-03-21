from persistent.mapping import PersistentMapping
from plone import api
from zope.annotation.interfaces import IAnnotations


# import base64
# import json


SESSION_KEY = "pas.plugins.oidc.session"


class Session:
    session_cookie_name: str = "__ac_session"
    _session: dict

    def __init__(self, request, use_session_data_manager=False):
        self.request = request

        self.use_session_data_manager = True
        portal = api.portal.get()
        if SESSION_KEY not in IAnnotations(portal):
            IAnnotations(portal)[SESSION_KEY] = PersistentMapping()
        self._session = IAnnotations(portal)[SESSION_KEY]

        # self.use_session_data_manager = use_session_data_manager
        # if self.use_session_data_manager:
        #     sdm = api.portal.get_tool("session_data_manager")
        #     self._session = sdm.getSessionData(create=True)
        # else:
        #     data = self.request.cookies.get(self.session_cookie_name) or {}
        #     if data:
        #         data = json.loads(base64.b64decode(data))
        #     self._session = data

    def set(self, name, value):
        self._session[name] = value
        # if self.use_session_data_manager:
        #     self._session.set(name, value)
        # else:
        #     if self.get(name) != value:
        #         self._session[name] = value
        #         self.request.response.setCookie(
        #             self.session_cookie_name,
        #             base64.b64encode(json.dumps(self._session).encode("utf-8")),
        #             path="/",   # ???
        #         )

    def get(self, name):
        return self._session[name]
        # if self.use_session_data_manager:
        return self._session.get(name)

    def keys(self):
        return self._session.keys()

    def __repr__(self):
        return repr(self._session)
