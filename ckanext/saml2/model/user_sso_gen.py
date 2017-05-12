from ckan.model import User
from sqlalchemy import Column, UnicodeText, ForeignKey, Boolean
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
import ckan.model as model

Base = declarative_base(bind=model.meta.engine)
metadata = Base.metadata
metadata.bind = model.meta.engine

# user_table = Table('user', metadata, autoload=True, autoload_with=model.meta.engine)
# user_table = Table('user', metadata, autoload=True)


class UserSsoGen(Base):
    __tablename__ = 'saml2_user_sso_gen'

    id = Column(UnicodeText, primary_key=True)
    # id = Column(UnicodeText, ForeignKey(User.id), primary_key=True)
    gen = Column(UnicodeText, nullable=False, unique=True)
    # user_name = Column(UnicodeText, default=None)
    user_name = Column(UnicodeText, nullable=False, unique=True)
    allow_update = Column(Boolean)

    # user = relationship(User, backref=backref(
    #     'saml2_sso', uselist=False,
    #     cascade="all, delete, delete-orphan")
    # )

    # def __repr__(self):
    #     return '<User SSO: username_old={0}, GEN={1}>'.format(
    #         self.user_name_old, self.gen
    #     )


def setupdb():

    metadata.create_all(model.meta.engine)


def dropdb():

    metadata.drop_all(model.meta.engine)
