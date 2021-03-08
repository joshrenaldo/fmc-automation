from fireREST.fmc import ChildResource


class DefaultAction(ChildResource):
    CONTAINER_NAME = 'AccessPolicy'
    CONTAINER_PATH = '/policy/prefilterpolicies/{uuid}'
    PATH = '/policy/prefilterpolicies/{container_uuid}/defaultactions/{uuid}'
    SUPPORTED_FILTERS = []
    SUPPORTED_PARAMS = []
    IGNORE_FOR_CREATE = []
    IGNORE_FOR_UPDATE = []
    MINIMUM_VERSION_REQUIRED_GET = '6.5.0'
    MINIMUM_VERSION_REQUIRED_UPDATE = '6.5.0'
