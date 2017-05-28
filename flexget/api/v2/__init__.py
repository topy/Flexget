from flask import Flask
from flask_compress import Compress
from flask_cors import CORS
from flask_graphql.graphqlview import GraphQLView

from flexget.api.v2.plugins.history import schema
from flexget.event import event
from flexget.manager import Session

v2_app = Flask(__name__)
CORS(v2_app, expose_headers='Link, Total-Count, Count, ETag')
Compress(v2_app)


@event('manager.initialize')
def register_view(manager):
    # Register graphql view to root, let cherry-py assign it to endpoint
    v2_app.add_url_rule('/',
                        view_func=GraphQLView.as_view('graphql',
                                                      schema=schema,
                                                      graphiql=True,
                                                      context={'session': Session()}))
