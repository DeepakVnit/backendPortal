import json

from rest_framework.renderers import JSONRenderer


class ConduitJSONRenderer(JSONRenderer):
    charset = 'utf-8'
    object_label = 'object'

    def render(self, data, media_type=None, renderer_context=None):
        errors = data.get('errors', None)

        if errors is not None:
            return super(ConduitJSONRenderer, self).render(data)

        return json.dumps({
            self.object_label: data
        })

class ProfileJSONRenderer(ConduitJSONRenderer):
    object_label = 'profile'


class UserJSONRenderer(ConduitJSONRenderer):
    charset = 'utf-8'
    object_label = 'user'

    def render(self, data, media_type=None, renderer_context=None):
        token = data.get('token', None)

        if token is not None and isinstance(token, bytes):
            data['token'] = token.decode('utf-8')
        return super(UserJSONRenderer, self).render(data)
