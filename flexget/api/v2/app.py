from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin
from future.utils import native_str

import graphene
from flask import Flask
from flask_compress import Compress
from flask_cors import CORS
from flask_graphql.graphqlview import GraphQLView

from flexget.event import event, fire_event
from flexget.manager import Session

v2_app = Flask(__name__)
CORS(v2_app, expose_headers='Link, Total-Count, Count, ETag')
Compress(v2_app)

types = []
query_attributes = []
methods = []


class Query(graphene.ObjectType):
    pass


fire_event('graphql.register', query_attributes, types, methods)

for att in query_attributes:
    for key, value in att.items():
        setattr(Query, key, value)

for meth in methods:
    for key, value in meth.items():
        setattr(Query, key, value)

schema = graphene.Schema(query=Query, types=types)


@event('manager.initialize')
def register_view(manager):
    # Register graphql view to root, let cherry-py assign it to endpoint
    v2_app.add_url_rule(native_str('/'), view_func=GraphQLView.as_view('graphql',
                                                                       schema=schema,
                                                                       graphiql=True,
                                                                       context={'session': Session()}))
