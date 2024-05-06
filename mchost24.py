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

class MCHost24APIError(Exception):
    """Parent Class for all error specific to the MC-Host24 API"""
    
    def __init__(self, message: str = None, endpoint: str = None):
        self.endpoint = endpoint
        
        if message is None:
            self.message = self.__doc__
        else:
            self.message = message
        
        if self.endpoint is not None:
            super().__init__(f"[{self.endpoint}] {self.message}")
        else:
            super().__init__(self.message)

class MCH24UnauthorizedError(MCHost24APIError):
    """Client is not authenticated to talk to the API"""

class MCH24LoginFailedError(MCHost24APIError):
    """Login to API failed"""

class MCH24UnknownEndpointError(MCHost24APIError):
    """Tried to access unknown API endpoint"""
    
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        super().__init__(f"Tried to access unknown API endpoint: {endpoint}", None)

class MCH24UnsupportedRequestMethodError(MCHost24APIError):
    """Tried to access endpoint with unsupported request method"""
    
    def __init__(self, endpoint: str, request_method: str):
        self.endpoint = endpoint
        super().__init__(f"Tried to access endpoint with unsupported request method: {request_method}", endpoint)


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
    
    # TODO: Handle error messages for queries not found e.g. /domain/606060/info
    if response.status_code == 404:
        try:
            resjson = response.json()
            
            if "resource not found" in resjson["message"]:
                raise MCH24UnknownEndpointError(endpoint)
            else:
                return response
        except Exception as e:
            raise MCHost24APIError("Error while parsing 404 response") from e
    elif response.status_code == 405:
        raise MCH24UnsupportedRequestMethodError(endpoint, method)
    elif response.status_code == 403:
        raise MCH24LoginFailedError()
    
    response.raise_for_status()
    
    return response

class HTTPTokenAuth(requests.auth.AuthBase):
    def __init__(self, token: str):
        self.token = token

    def __eq__(self, other: object):
        return self.token == getattr(other, 'token', None)

    def __ne__(self, other: object):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = self.token
        return r

class APIResponseStatus(Enum):
    """ Enum representing the status of an API response """
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    UNAUTHORIZED = 401

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
    def __init__(self, token: str = None):
        if token:
            self.auth = HTTPTokenAuth(token)
        else:
            self.auth = None
    
    def set_token(self, token: str):
        """ Set API token """
        self.auth = HTTPTokenAuth(token)
    
    def get_token(self, username: str, password: str, tfa: int = None):
        """ Gets an API token from the API using a user's credentials """
        
        endpoint = "/token"
        payload = {
            "username": username,
            "password": password,
            "tfa": tfa
        }
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("post", endpoint, json=payload, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        # Try to parse into response object and catch malformed API request with special case
        try:
            response = APIResponse.from_dict(response)
            
            if response.status == APIResponseStatus.UNAUTHORIZED:
                raise MCH24UnauthorizedError()

            return response
        except KeyError as e:
            # Workaround for issue with API
            # Sometimes, an API response will not match the schema and have missing values
            # In such cases, default values are inserted into the response object
            response["data"] = response.get("data", [])
            response["status"] = response.get("status", "ERROR")
            response["meta"] = response.get("meta", {
                    'warnings': [],
                    'errors': [],
                    'success': []
                })
            response["reload_datatables"] = response.get("reload_datatables", False)
            response["reload"] = response.get("reload_datatables", False)
            
            response["messages"] = response.get("messages", None)
            response["message"] = response.get("message", None)
            
            if response["messages"] is None:
                response["messages"] = [response["message"]]
            elif response["message"] is None:
                messages = []
                
                # Collect all messages
                for k in response["messages"]:
                    for m in response["messages"][k]:
                        messages.append(m)
                
                response["messages"] = messages
                response["message"] = response["messages"][0] if len(response["messages"]) > 0 else ""
            
            return APIResponse.from_dict(response)