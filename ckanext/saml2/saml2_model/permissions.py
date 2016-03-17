from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import (
  Column,
  UnicodeText,
)
from ckan.model.domain_object import DomainObject


from ckanext.saml2.saml2_model.base import Base


class AccessPermissions(Base, DomainObject):
  """Model for handling permissions."""

  __tablename__ = "access_permissions"

  owner_id = Column(
    UnicodeText,
    nullable=False,
    primary_key=True
  )

  permissions = Column(
    ARRAY(UnicodeText),
    default=[],
    nullable=False
  )

  def __repr__(self):
    """String representation."""
    return "<AccessPermissions owner='%s' permissions='%s'>" % (
      self.owner_id, self.permissions)

  def has_permission(self, permission):
    """Check whether user has this permission."""
    return permission in self.permissions

  def add_permission(self, permission):
    """Assign permission to user."""
    if permission not in self.permissions:
      self.permissions.append(permission)
    return self

  def set_permissions(self, permissions):
    """Rewrite user's permissions to user."""
    self.permissions = permissions
    return self

  def remove_permission(self, permission):
    """Remove permission from user."""
    if permission in self.permissions:
      self.permissions.remove(permission)
    return self
