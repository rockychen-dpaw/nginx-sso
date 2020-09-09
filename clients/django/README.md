django app for nginx sso
=========

This app can enable nginx sso support.

Install:
 * Copy nginx_sso to application root folder.

Settings:
 * add "nginx_sso" to INSTALLED_APPS
 * add "nginx_sso.middleware.NginxAuthMiddleware" after or replace the middleware "django.contrib.auth.middleware.AuthenticationMiddleware" to MIDDLEWARE_CLASSES
 * add "nginx_sso.backends.NginxAuthBackend" to AUTHENTICATION_BACKENDS

