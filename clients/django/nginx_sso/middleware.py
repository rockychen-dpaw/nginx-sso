import json

from django.contrib import auth
from django.contrib.auth.middleware import RemoteUserMiddleware

class NginxAuthMiddleware(RemoteUserMiddleware):
    header = "HTTP_REMOTE_USER"
    roles_header = "HTTP_REMOTE_USER_ROLES"
    profile_header = "HTTP_REMOTE_USER_PROFILE"
    auth_header = "HTTP_REMOTE_USER_AUTH"

    def process_request(self,request):
        ###################################################################################
        ##Code Copied from RemoteUserMiddleware,  just comment auth.login(reuqest.user) ###
        ##############################################################################$####
        # AuthenticationMiddleware is required so that request.user exists.
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The Django remote user auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the RemoteUserMiddleware class.")
        try:
            username = request.META[self.header]
        except KeyError:
            # If specified header doesn't exist then remove any existing
            # authenticated remote-user, or return (leaving request.user set to
            # AnonymousUser by the AuthenticationMiddleware).
            if request.user.is_authenticated():
                self._remove_invalid_user(request)
            return
        # If the user is already authenticated and that user is the user we are
        # getting passed in the headers, then the correct user is already
        # persisted in the session and we don't need to continue.
        if request.user.is_authenticated():
            if request.user.get_username() == self.clean_username(username, request):
                return
            else:
                # An authenticated user is associated with the request, but
                # it does not match the authorized user in the header.
                self._remove_invalid_user(request)

        # We are seeing this user for the first time in this session, attempt
        # to authenticate the user.
        user = auth.authenticate(remote_user=username)
        if user:
            # User is valid.  Set request.user and persist user in the session
            # by logging the user in.
            request.user = user
            user_auth = request.META[self.auth_header]
            if not user_auth or user_auth != "basic":
                auth.login(request, user)

        ###################################################################################

        if request.user and request.user.is_authenticated():
            #user is authenticated
            user_roles = []
            try:
                user_roles_str = request.META[self.roles_header]
                if user_roles_str:
                    user_roles = [r.strip() for r in user_roles_str.split(";")]
            except:
                pass

            request.user._groups = user_roles
            request.user.is_staff = False
            request.user.is_active = True
            request.user.is_superuser = "admin" in user_roles

            user_profile = {}
            try:
                user_profile_str = request.META[self.profile_header]
                if user_profile_str:
                    user_profile = json.loads(user_profile_str)
            except:
                pass

            request.user.first_name = user_profile.get("first_name",None)
            request.user.last_name = user_profile.get("last_name",None)
            request.user.email = user_profile.get("email",None)


           
