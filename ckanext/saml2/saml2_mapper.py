role_equality = dict(
    member='member',
    reader='member',
    editor='editor',
    admin='admin'
)


def nsw_org_mapper(saml_info):
    """Prepare org_dict using org=role[,role][|repeat] format."""
    tenancy = saml_info.get('tenancy', [])
    if tenancy:
        org_dict = dict([
            _get_privileged_role(*part.split('='))
            for part in tenancy[0].split('|')
        ])
        return org_dict


def _get_privileged_role(org, roles, separator=','):
    """Return tuple with organization and most privileged role."""
    capacity = sorted([role_equality.get(
        role, 'member') for role in roles.split(separator)]).pop(0)

    return org, dict(capacity=capacity)
