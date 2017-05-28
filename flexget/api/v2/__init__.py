from flask import Flask
from flask_graphql.graphqlview import GraphQLView

from flexget.api.v2.plugins.history import schema
from flexget.event import event
from flexget.manager import Session

v2_app = Flask(__name__)


@event('manager.initialize')
def register_view(manager):
    v2_app.add_url_rule('/',
                        view_func=GraphQLView.as_view('graphql',
                                                      schema=schema,
                                                      graphiql=True,
                                                      context={'session': Session()}))
