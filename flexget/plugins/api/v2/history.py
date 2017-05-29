from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin

import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType, SQLAlchemyConnectionField

from flexget.event import event
from flexget.plugins.output.history import History as HistoryModel


class History(SQLAlchemyObjectType):
    class Meta:
        model = HistoryModel


def resolve_history(self, args, context, info):
    query = History.get_query(context)
    return query.all()


@event('graphql.register')
def register_graphql_schema(query_attributes, types, methods):
    query_attributes.append({'history': graphene.List(History)})
    types.append(History)
    methods.append({'resolve_history': resolve_history})
