from django.db import DEFAULT_DB_ALIAS, connections
from django.db.models.fields.related_descriptors import ReverseOneToOneDescriptor


def attach_foreignkey(objects, field, related=(), database=None):
    """
    Shortcut method which handles a pythonic LEFT OUTER JOIN.

    ``attach_foreignkey(posts, Post.thread)``

    Works with both ForeignKey and OneToOne (reverse) lookups.
    """

    if not objects:
        return

    if database is None:
        database = list(objects)[0]._state.db

    is_foreignkey = isinstance(field, ReverseOneToOneDescriptor)

    if not is_foreignkey:
        field = field.field
        accessor = "_%s_cache" % field.name
        model = field.remote_field.model
        lookup = "pk"
        column = field.column
        key = lookup
    else:
        accessor = field.cache_name
        field = field.related.field
        model = field.model
        lookup = field.name
        column = "pk"
        key = field.column

    objects = [o for o in objects if (related or getattr(o, accessor, False) is False)]

    if not objects:
        return

    # Ensure values are unique, do not contain already present values, and are not missing
    # values specified in select_related
    values = {_f for _f in (getattr(o, column) for o in objects) if _f}
    if values:
        qs = model._default_manager
        if database:
            qs = qs.using(database)
        if related:
            qs = qs.select_related(*related)

        if len(values) > 1:
            qs = qs.filter(**{"%s__in" % lookup: values})
        else:
            qs = [qs.get(**{lookup: next(iter(values))})]

        queryset = {getattr(o, key): o for o in qs}
    else:
        queryset = {}

    for o in objects:
        setattr(o, accessor, queryset.get(getattr(o, column)))


def table_exists(name, using=DEFAULT_DB_ALIAS):
    return name in connections[using].introspection.table_names()
