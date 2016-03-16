from ckan.model import Session
from saml2_model.permissions import AccessPermissions as APModel


class AccessPermissions:
  """Implementation of access permissions in CKAN."""

  _available_permissions = []

  def permissions_list(self):
    """Show all available permissions."""
    return self._available_permissions

  def permission_exists(self, permission):
    """Check whether list of permissions contains this permission."""
    return permission in self._available_permissions

  def create_permission(self, permission):
    """Add permission to list."""
    if permission not in self._available_permissions:
      self._available_permissions.append(permission)
    return self

  def destroy_permission(self, permission):
    """Remove permission from list."""
    if permission in self._available_permissions:
      self._available_permissions.remove(permission)
    return self

  def get_user_permissions(self, id):
    """Get object with user's permissions."""
    permissions = Session.query(APModel).get(id)
    return permissions

  def humanize_permission(self, perm):
    """Convert permission's name to title format."""
    return perm.replace('_', ' ').title()


ACCESS_PERMISSIONS = AccessPermissions()
