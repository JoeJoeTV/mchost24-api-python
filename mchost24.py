import requests
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from typing import Union, List
from enum import Enum
import json
from urllib.parse import urljoin
import pprint
import logging

logging.getLogger().setLevel(logging.DEBUG)

#
#   Constants
#

VERSION = "0.0.1"
API_URL = "https://mc-host24.de/api/v1/"
USER_AGENT = f"mchost-api-python/{VERSION}"

#
#   Helper Classes/Functions
#

def api_request(method: str, endpoint: str, json=None, auth=None, **kwargs):
    r"""Perform HTTP request to API endpoint"""
    
    headers = {
        "accept": "application/json",
        "user-agent": USER_AGENT
    }
    url = urljoin(API_URL, endpoint.lstrip("/"))
    logging.debug("Request URL: " + url)

    response = requests.request(method, url, json=json, auth=auth, headers=headers, **kwargs)
    logging.debug(pprint.pformat(response.json(), compact=True).replace("'",'"'))
    return response

class HTTPTokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return self.token == getattr(other, 'token', None)

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = self.token
        return r

class MCHost24APIError(Exception):
    """Parent Class for all error specific to the MC-Host24 API"""
    
    def __init__(self, message, endpoint=None):
        self.endpoint = endpoint
        
        if message is None:
            self.message = self.__doc__
        else:
            self.message = message
        
        if endpoint is not None:
            super().__init__(f"[{endpoint}] {message}")
        else:
            super().__init__(message)

class NotAuthenticatedError(MCHost24APIError):
    """Client is not authenticated to talk to the API"""

class APIResponseStatus(Enum):
    """ Enum representing the status of an API response """
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"

#
#   API Data Classes
#

@dataclass_json
@dataclass
class APIMeta:
    warnings: List[str]
    errors: List[str]
    success: List[str]

@dataclass_json
@dataclass
class APIResponseToken:
    api_token: str

@dataclass_json
@dataclass
class APIResponse:
    """ Data class representing an API response """
    data: Union[APIResponseToken, object, list]
    status: APIResponseStatus
    meta: APIMeta
    success: bool
    messages: List[str]
    message: str
    reload_datatables: bool
    reload: bool

#
#   Main Class
#

class MCHost24API:
    def __init__(self, token=None):
        if token:
            self.auth = HTTPBearerAuth
    
    def set_token(self, token: str):
        """ Set API token """
        self.auth = HTTPBearerAuth(token)
    
    def get_token(self, username: str, password: str, tfa: int = None):
        """ Gets an API token from the API using a user's credentials """
        
        endpoint = "/token"
        payload = {
            "username": username,
            "password": password,
            "tfa": tfa
        }
        
        try:
            response = api_request("post", endpoint, json=payload, auth=self.auth).json()
            
            # The request was not successful, but we have an error message
            if not response["success"]:
                # Hack because of weird API behaviour
                if "message" in response:
                    raise MCHost24APIError(response["message"], endpoint)
                else:
                    raise MCHost24APIError(str(response["messages"]), endpoint)
            
            # The request was successful, so return API Token
            return APIResponse.from_dict(response)
        except (requests.RequestException, TypeError, AttributeError, ValueError, KeyError) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e