from django.apps import AppConfig

class AutheticationAppConfig(AppConfig):
    name = "portalapp"
    label = "portalapp"
    verbose_name = "portalapp"

    def ready(self):
        from portalapp import signals

default_app_config = "portalapp.AutheticationAppConfig"
