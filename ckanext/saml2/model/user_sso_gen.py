from sqlalchemy import Column, UnicodeText, Boolean
from sqlalchemy.ext.declarative import declarative_base
import ckan.model as model

Base = declarative_base()
metadata = Base.metadata


class UserSsoGen(Base):
    __tablename__ = 'saml2_user_sso_gen'

    id = Column(UnicodeText, primary_key=True)
    gen = Column(UnicodeText, nullable=False, unique=True)
    user_name = Column(UnicodeText, nullable=False, unique=True)
    allow_update = Column(Boolean)
    state = Column(UnicodeText, default='active')


def setupdb():

    metadata.create_all(model.meta.engine)


def dropdb():

    metadata.drop_all(model.meta.engine)
