from ckan.model import User
from sqlalchemy import Column, UnicodeText, ForeignKey
from ckanext.saml2.model import Base


class UserSsoGen(Base):
    __tablename__ = 'saml2_user_sso_gen'

    user_id = Column(UnicodeText, primary_key=True)
    # user_id = Column(UnicodeText, ForeignKey(User.id), primary_key=True)
    gen = Column(UnicodeText, default=None)
    user_name = Column(UnicodeText, default=None)
    # user_name = Column(UnicodeText, nullable=False, unique=True)
