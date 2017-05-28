import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType
from flexget.plugins.output.history import History as HistoryModel


class History(SQLAlchemyObjectType):
    class Meta:
        model = HistoryModel


class Query(graphene.ObjectType):
    history = graphene.List(History)

    def resolve_history(self, args, context, info):
        query = History.get_query(context)  # SQLAlchemy query
        return query.all()


schema = graphene.Schema(query=Query, types=[History])
