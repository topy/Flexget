import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType

from flexget.event import event
from flexget.plugins.output.history import History as HistoryModel


class History(SQLAlchemyObjectType):
    class Meta:
        model = HistoryModel


def resolve_history(self, args, context, info):
    query = History.get_query(context)
    return query.all()


@event('graphql.register')
def register_graphql_schema(query, types):
    setattr(query, 'history', graphene.List(History))
    query.resolve_history = resolve_history
