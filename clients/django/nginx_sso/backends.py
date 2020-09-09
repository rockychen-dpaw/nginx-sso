
from django.contrib.auth.backends import RemoteUserBackend
from django.contrib.auth.models import Permission

class NginxAuthBackend(RemoteUserBackend):
    create_unknown_user = True

    def get_group_permissions(self, user_obj, obj=None):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """
        if user_obj.is_anonymous() or obj is not None:
            return set()
        if hasattr(user_obj, '_group_perm_cache'):
            return user_obj._group_perm_cache

        if user_obj.is_superuser:
            perms = Permission.objects.all()
        elif hasattr(user_obj,"_groups"):
            perms = Permission.objects.filter(group__name__in=user_obj._groups)
        else:
            perms = None

        if perms:
            perms = perms.values_list('content_type__app_label', 'codename').order_by()
            user_obj._group_perm_cache = set("%s.%s" % (ct, name) for ct, name in perms)
            return user_obj._group_perm_cache
        else:
            return set()

        return user_obj._group_perm_cache

