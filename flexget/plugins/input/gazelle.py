from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin

from datetime import datetime
import logging

from flexget import plugin, db_schema
from flexget.config_schema import one_or_more
from flexget.entry import Entry
from flexget.event import event
from flexget.manager import Session as FlexgetSession
from flexget.plugin import PluginError
from flexget.utils.database import json_synonym
from flexget.utils.requests import Session, TokenBucketLimiter
from flexget.utils.search import normalize_unicode
from sqlalchemy import Column, Unicode, String, DateTime


DETECT_2FA = ("Authenticator Code", "TOTP code")
log = logging.getLogger('gazelle')
Base = db_schema.versioned_base('gazelle_session', 0)


class GazelleSession(Base):
    __tablename__ = 'gazelle_session'

    username = Column(Unicode, primary_key=True)
    base_url = Column(String, primary_key=True)

    authkey = Column(String)
    passkey = Column(String)
    _cookies = Column('cookie', Unicode)
    cookies = json_synonym('_cookies')
    expires = Column(DateTime)


class InputGazelle(object):
    """A plugin that searches a Gazelle-based website"""

    # Aliases for config -> api params
    ALIASES = {
        "search": "searchstr"
    }

    # API parameters
    # None means a raw value entry (no validation other than schema)
    # A dict means an enum with a config -> api mapping
    # A list is an enum with no mapping
    PARAMS = {
        "searchstr": None
    }

    def __init__(self):
        self.base_url = None
        self.schema = {
            'type': 'object',
            'properties': {
                'base_url': {'type': 'string'},
                'username': {'type': 'string'},
                'password': {'type': 'string'},
                'user_agent': {'type': 'string'},
                'search': {'type': 'string'},
            },
            'required': ['base_url', 'username', 'password'],
            'additionalProperties': False
        }

    def _key(self, key):
        """Gets the API key name from the entered key"""
        if key in self.ALIASES:
            return self.ALIASES[key]
        return key

    def _opts(self, key):
        """Gets the options for the specified key"""
        return self.PARAMS[self._key(key)]

    def _getval(self, key, val):
        """Gets the value for the specified key based on a config option"""
        opts = self._opts(key)
        if isinstance(opts, dict):
            # Translate the input value to the API value
            # The str cast converts bools to 'True'/'False' for use as keys
            # This allows for options that have True/False/Other values
            return opts[str(val)]
        elif isinstance(val, list):
            # Fix yaml parser making a list out of a string
            return ",".join(val)
        return val

    def params_from_config(self, config):
        """Filter params and map config values -> api values"""
        ret = {}
        for k, v in config.items():
            key = self._key(k)
            if key in self.PARAMS:
                ret[key] = self._getval(k, v)
        return ret

    def setup(self, task, config):
        """Set up a session and log in"""
        self._session = Session()
        base_url = config.get('base_url', "").rstrip("/")
        if base_url:
            if self.base_url and self.base_url != base_url:
                log.warning("Using plugin designed for %s on %s - "
                            "things may break", self.base_url, base_url)
            self.base_url = base_url

        if not self.base_url:
            raise PluginError("No 'base_url' configured")

        # The consistent request limiting rule seems to be:
        # "Refrain from making more than five (5) requests every ten (10) seconds"
        self._session.add_domain_limiter(TokenBucketLimiter(self.base_url, 2, '2 seconds'))

        # Custom user agent
        user_agent = config.get('user_agent', "Flexget [Gazelle plugin]")
        if user_agent:
            self._session.headers.update({"User-Agent": user_agent})
        self.username = config['username']
        self.password = config['password']

        # Login
        self.authenticate()

        # Logged in successfully, it's ok if nothing matches now
        task.no_entries_ok = True


    def authenticate(self, force=False):
        """
        Log in and store auth data from the server
        Adapted from https://github.com/isaaczafuta/whatapi
        """

        # clean slate before creating/restoring cookies
        self._session.cookies.clear()

        if not force:
            with FlexgetSession() as session:
                db_session = session.query(GazelleSession).filter(
                    GazelleSession.base_url == self.base_url,
                    GazelleSession.username == self.username
                ).one_or_none()
                if (db_session and db_session.expires and
                        db_session.expires >= datetime.utcnow()):
                    # Found a valid session in the DB - use it
                    self._session.cookies.update(db_session.cookies)
                    self.authkey = db_session.authkey
                    self.passkey = db_session.passkey
                    log.info("Logged in to %s using cached session", self.base_url)
                    return

        # Forcing a re-login or no session in DB - log in using provided creds
        url = "{}/login.php".format(self.base_url)
        data = {
            'username': self.username,
            'password': self.password,
            'keeplogged': 1,
        }
        r = self._session.post(url, data=data, allow_redirects=False)
        if not r.is_redirect or r.next.url != "{}/index.php".format(self.base_url):
            msg = "Failed to log into {}".format(self.base_url)
            for x in DETECT_2FA:
                if x in r.text:
                    msg += " - Accounts using 2FA are currently not supported"
                    break
            raise PluginError(msg)

        accountinfo = self.request(no_login=True, action='index')
        self.authkey = accountinfo['authkey']
        self.passkey = accountinfo['passkey']
        log.info("Logged in to %s", self.base_url)

        # Store new session in DB
        log.debug("Storing session info in DB")
        with FlexgetSession() as session:
            expires = None
            for c in self._session.cookies:
                if c.name == "session":
                    expires = datetime.utcfromtimestamp(c.expires)
            db_session = GazelleSession(username=self.username,
                                        base_url=self.base_url,
                                        cookies=dict(self._session.cookies),
                                        expires=expires, authkey=self.authkey,
                                        passkey=self.passkey)
            session.merge(db_session)

    def request(self, no_login=False, **params):
        """
        Make an AJAX request to the API

        If `no_login` is True, logging in will not be attempted if the request
        is redirected to the login page.

        Adapted from https://github.com/isaaczafuta/whatapi
        """
        if 'action' not in params:
            raise ValueError("An 'action' is required when making a request")

        ajaxpage = "{}/ajax.php".format(self.base_url)
        r = self._session.get(ajaxpage, params=params, allow_redirects=False)
        if (not no_login and r.is_redirect and
                r.next.url == "{}/login.php".format(self.base_url)):
            log.warning("Redirected to login page, reauthenticating and trying again")
            self.authenticate(force=True)
            return self.request(no_login=True, **params)

        if r.status_code != 200:
            raise PluginError("{} returned a non-200 status code"
                              "".format(self.base_url))

        try:
            json_response = r.json()
            if json_response['status'] != "success":

                # Try to deal with errors returned by the API
                error = json_response.get('error', json_response.get('status'))
                if not error or error == "failure":
                    error = json_response.get('response', str(json_response))

                raise PluginError("{} gave a failure response of '{}'"
                                  "".format(self.base_url, error))
            return json_response['response']
        except (ValueError, TypeError, KeyError):
            raise PluginError("{} returned an invalid response"
                              "".format(self.base_url))

    def search_results(self, params):
        """Generator that yields search results"""
        page = 1
        pages = None
        while True:
            if pages and page >= pages:
                break

            log.debug("Attempting to get page %d of search results", page)
            result = self.request(action='browse', page=page, **params)
            if not result['results']:
                break
            for x in result['results']:
                yield x

            pages = result.get('pages', pages)
            page += 1

    def get_entries(self, search_results):
        """Generator that yields Entry objects from search results"""
        for result in search_results:
            # Get basic information on the release
            info = dict((k, result[k]) for k in ('groupId', 'groupName'))

            # Releases can have multiple download options
            for tor in result['torrents']:
                temp = info.copy()
                temp.update(dict((k, tor[k])
                            for k in ('torrentId',)))

                yield Entry(
                    title="{groupName} ({groupId} - {torrentId}).torrent".format(**temp),
                    url="{}/torrents.php?action=download&"
                        "id={}&authkey={}&torrent_pass={}"
                        "".format(self.base_url, temp['torrentId'], self.authkey, self.passkey),
                    torrent_seeds=tor['seeders'],
                    torrent_leeches=tor['leechers'],
                    # Size is returned in bytes, convert to MB for compat with the content_size plugin
                    content_size=tor['size'] / (1024 ** 2)
                )

    @plugin.internet(log)
    def search(self, task, entry, config):
        """Search interface"""
        self.setup(task, config)

        entries = set()
        params = self.params_from_config(config)
        for search_string in entry.get('search_strings', [entry['title']]):
            query = normalize_unicode(search_string)
            params[self._key('search')] = query
            entries.update(self.get_entries(self.search_results(params)))
        return entries

    @plugin.internet(log)
    def on_task_input(self, task, config):
        """Task input interface"""
        self.setup(task, config)

        params = self.params_from_config(config)
        return list(self.get_entries(self.search_results(params)))


class InputRedacted(InputGazelle):
    """A plugin that searches RED"""

    ALIASES = {
        "artist": "artistname",
        "album": "groupname",
        "leech_type": "freetorrent",
        "release_type": "releasetype",
        "tags": "taglist",
        "tag_type": "tags_type",
        "search": "searchstr",
        "log": "haslog",
    }

    PARAMS = {
        "searchstr": None,
        "taglist": None,
        "artistname": None,
        "groupname": None,
        "year": None,
        "tags_type": {
            "any": 0,
            "all": 1,
        },
        "encoding": [
            "192", "APS (VBR)", "V2 (VBR)", "V1 (VBR)", "256", "APX (VBR)",
            "V0 (VBR)", "320", "Lossless", "24bit Lossless", "Other"
        ],
        "format": [
            "MP3", "FLAC", "AAC", "AC3", "DTS"
        ],
        "media": [
            "CD", "DVD", "Vinyl", "Soundboard", "SACD", "DAT", "Cassette",
            "WEB", "Blu-ray"
        ],
        "releasetype": {
            "album": 1,
            "soundtrack": 3,
            "EP": 5,
            "anthology": 6,
            "compilation": 7,
            "single": 9,
            "live album": 11,
            "remix": 13,
            "bootleg": 14,
            "interview": 15,
            "mixtape": 16,
            "demo": 17,
            "concert recording": 18,
            "dj mix": 19,
            "unknown": 21,
        },
        "haslog": {
            "False": 0,
            "True": 1,
            "100%": 100,
            "<100%": -1
        },
        "freetorrent": {
            "freeleech": 1,
            "neutral": 2,
            "either": 3,
            "normal": 0,
        },
        "hascue": {
            "False": 0,
            "True": 1,
        },
        "scene": {
            "False": 0,
            "True": 1,
        },
        "vanityhouse": {
            "False": 0,
            "True": 1,
        }
    }

    def __init__(self):
        """Init client and set up the schema"""
        super().__init__()

        self.base_url = "https://redacted.ch"
        self.schema = {
            'type': 'object',
            'properties': {
                'base_url': {'type': 'string'},
                'username': {'type': 'string'},
                'password': {'type': 'string'},
                'user_agent': {'type': 'string'},
                'search': {'type': 'string'},
                'artist': {'type': 'string'},
                'album': {'type': 'string'},
                'year': {'type': ['string', 'integer']},
                'tags': one_or_more({'type': 'string'}),
                'tag_type': {'type': 'string', 'enum': list(self._opts('tag_type').keys())},
                'encoding': {'type': 'string', 'enum': self._opts('encoding')},
                'format': {'type': 'string', 'enum': self._opts('format')},
                'media': {'type': 'string', 'enum': self._opts('media')},
                'release_type': {'type': 'string', 'enum': list(self._opts('release_type').keys())},
                'log': {'oneOf': [{'type': 'string', 'enum': list(self._opts('log').keys())}, {'type': 'boolean'}]},
                'leech_type': {'type': 'string', 'enum': list(self._opts('leech_type').keys())},
                'hascue': {'type': 'boolean'},
                'scene': {'type': 'boolean'},
                'vanityhouse': {'type': 'boolean'},
            },
            'required': ['username', 'password'],
            'additionalProperties': False
        }

    def get_entries(self, search_results):
        """Generator that yields Entry objects from search results"""
        for result in search_results:
            # Get basic information on the release
            info = dict((k, result[k]) for k in ('artist', 'groupName', 'groupYear'))

            # Releases can have multiple download options
            for tor in result['torrents']:
                temp = info.copy()
                temp.update(dict((k, tor[k])
                            for k in ('media', 'encoding', 'format', 'torrentId')))

                yield Entry(
                    title="{artist} - {groupName} - {groupYear} "
                          "({media} - {format} - {encoding})-{torrentId}.torrent".format(**temp),
                    url="{}/torrents.php?action=download&"
                        "id={}&authkey={}&torrent_pass={}"
                        "".format(self.base_url, temp['torrentId'], self.authkey, self.passkey),
                    torrent_seeds=tor['seeders'],
                    torrent_leeches=tor['leechers'],
                    # Size is returned in bytes, convert to MB for compat with the content_size plugin
                    content_size=tor['size'] / (1024 ** 2)
                )


class InputNotWhat(InputRedacted):
    """A plugin that searches NWCD"""

    def __init__(self):
        # Tweak params from the superclass before calling it
        self.PARAMS['releasetype']['demo'] = 22
        self.PARAMS['releasetype']['dj mix'] = 23
        self.PARAMS['releasetype']['concert recording'] = 24
        self.PARAMS['encoding'].append('q8.x (VBR)')
        self.PARAMS['media'].append('Other')
        self.PARAMS['haslog'] = {
            "False": 0,
            "True": 1,
            "gold": 102,
            "silver": 101,
            "gold/silver": 100,
            "lineage": -5,
            "unscored": -1,
            "missing lineage": -6,
            "missing dr score": -7,
            "missing sample rate": -8,
            "missing description": -9
        }
        super().__init__()
        self.base_url = "https://notwhat.cd"


@event('plugin.register')
def register_plugin():
    plugin.register(InputGazelle, 'gazelle', interfaces=['task', 'search'], api_ver=2)
    plugin.register(InputRedacted, 'redactedch', interfaces=['task', 'search'], api_ver=2)
    plugin.register(InputNotWhat, 'notwhatcd', interfaces=['task', 'search'], api_ver=2)
