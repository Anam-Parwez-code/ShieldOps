"""Helpers to resolve lookup records by primary key or legacy code string."""


def resolve_lookup(model, value, field_name='code'):
    """Accept int/str id or code string; return model instance or None."""
    if value is None or value == '':
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        try:
            return model.objects.get(pk=int(value))
        except model.DoesNotExist:
            return None
    try:
        return model.objects.get(**{field_name: str(value).upper()})
    except model.DoesNotExist:
        # Legacy alias: MANAGER -> FINANCE_MANAGER
        aliases = {'MANAGER': 'FINANCE_MANAGER', 'PENDING': 'PENDING_VERIFICATION'}
        alias = aliases.get(str(value).upper())
        if alias:
            try:
                return model.objects.get(**{field_name: alias})
            except model.DoesNotExist:
                return None
        return None


def lookup_choices(model):
    """Return choice list for API endpoints."""
    return [
        {'id': obj.id, 'code': obj.code, 'label': obj.label}
        for obj in model.objects.filter(is_active=True)
    ]


def default_lookup(model, default_code):
    return model.objects.filter(code=default_code, is_active=True).first()
