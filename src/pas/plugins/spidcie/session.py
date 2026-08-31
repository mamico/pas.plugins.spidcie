from BTrees.OOBTree import OOBTree
from plone import api
from zope.annotation.interfaces import IAnnotations


# import base64
# import json


SESSION_KEY = "pas.plugins.spidcie.session"


class Session:
    session_cookie_name: str = "__ac_session"
    _session: dict

    def __init__(self, request, use_session_data_manager=False):
        self.request = request

        self.use_session_data_manager = True
        portal = api.portal.get()
        annotations = IAnnotations(portal)
        store = annotations.get(SESSION_KEY)
        if not isinstance(store, OOBTree):
            # First access after upgrade, or brand new store: (re)create it as
            # an OOBTree so that every login only rewrites the bucket it
            # touches instead of the whole mapping (see #45 growth issue).
            # Migrate any pre-existing PersistentMapping data in place; this
            # single migration commit rewrites the old store once, then the
            # problem is closed.
            new_store = OOBTree()
            if store:
                new_store.update(store)
            annotations[SESSION_KEY] = new_store
            store = new_store
        self._session = store

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

    def get(self, name, default=None):
        return self._session.get(name, default)

    def pop(self, name, default=None):
        """Remove and return an entry, e.g. to consume a one-time OIDC state.

        Using pop (rather than get) at the callback makes the state
        single-use, which is also the correct defense against replay of the
        callback, and keeps the store from growing unbounded (see #45).
        """
        return self._session.pop(name, default)

    def keys(self):
        return self._session.keys()

    def __repr__(self):
        return repr(self._session)
