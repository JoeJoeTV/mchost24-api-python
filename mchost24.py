import requests
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from typing import Union, List
from enum import Enum

#
#   Constants
#

VERSION = "0.0.1"
API_URL = "https://mc-host24.de/api/v1/"
USER_AGENT = f"mchost-api-python/{VERSION}"

#
#   Helper Classes/Functions
#

class MCHost24APIError(Exception):
    """Parent Class for all error specific to the MC-Host24 API"""
    
    def __init__(self, message):
        if message is None:
            self.message = self.__doc__
        else:
            self.message = message
        
        super().__init__(self.message)

class NotAuthenticatedError(MCHost24APIError):
    """Client is not authenticated to talk to the API"""

class APIResponseStatus(Enum):
    """ Enum representing the status of an API response """
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"

#
#   API Data Classes
#

@dataclass
class APIMeta:
    warnings: List[str]
    errors: List[str]
    success: List[str]

@dataclass
@dataclass_json
class APIResponse:
    """ Data class representing an API response """
    data: Union[object, list]
    status: APIResponseStatus
    meta: APIMeta
    success: bool
    messages: List[str]
    reload_datatables: bool
    reload: bool

#
#   Main Class
#

class MCHost24API:
    def __init__(self):
        self.token = None
    
    def set_token(self, token):
        """ Set API token """
        self.token = token