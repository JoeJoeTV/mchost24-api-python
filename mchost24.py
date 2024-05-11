import requests
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from typing import Union, List
from enum import Enum
import json
from urllib.parse import urljoin
import pprint
import logging
from datetime import datetime

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


def api_request(method: str, endpoint: str, json: dict = None, auth: requests.auth.AuthBase = None, **kwargs) -> requests.Response:
    """Perform HTTP request to API endpoint
    
    Args:
        method:     The HTTP request method to use for the request
        endpoint:   The API endpoint of the MC-Host24 API to send the request to
        [json]:     The JSON data payload to send as a dictionary
        [auth]:     The authentication object to use for authenticating with the API
        **kwargs:   Any other keyword arguments to pass onto the requests.request method
    
    Returns:
        The response to the HTTP request
    """
    
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

def fix_api_response(response: dict) -> dict:
    """ Fixes malformed API responses with missing fields by loading defaults and handling edge cases """
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
    
    if (response["messages"] is None) and (response["message"] is not None):
        response["messages"] = [response["message"]]
    elif (response["message"] is None) and (response["messages"] is not None):
        messages = []
        
        # Collect all messages
        for k in response["messages"]:
            for m in response["messages"][k]:
                messages.append(m)
        
        response["messages"] = messages
        response["message"] = response["messages"][0] if len(response["messages"]) > 0 else ""
    else:
        response["messages"] = []
        response["message"] = ""

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
    warnings: List[str] # Translated warnings
    errors: List[str]   # Translated errors
    success: List[str]  # Translated success messages

@dataclass_json
@dataclass
class APIResponseToken:
    api_token: str  # API Token to be used for authentication

@dataclass_json
@dataclass
class APIResponseMinecraftServer:
    id: int                         # The MC-HOST24 database id
    service_id: int                 # The MC-HOST24 service id
    service_ordered_at: datetime    # Time at which the product was ordered
    expire_at: datetime             # Time at which the product should expire
    expired_at: datetime | None     # Time at which the product expired
    product_name: str | None        # The product name
    multicraft_id: int              # The multicraft panel id
    address: str                    # The ipv4 address of the minecraft server with port
    memory: int                     # Memory in Mebibyte
    online: bool                    # Current status of minecraft server
    players_online: int             # Current online players on minecraft server
    players_max: int                # Maximal online players on minecraft server
    cpu_usage: int                  # Current cpu usage of minecraft-server in percentage
    mem_usage: int                  # Current memory usage of minecraft-server in percentage

# Type definitions
APIDataSingle = APIResponseToken | APIResponseMinecraftServer
APIDataList = APIResponseMinecraftServer

@dataclass_json
@dataclass
class APIResponse:
    """ Data class representing an API response """
    data: APIDataSingle | list[APIDataList] # Data returned by the API
    status: APIResponseStatus   # Status of the API request
    meta: APIMeta               # Translated messages used in messages
    success: bool               # Whether the API request was successful
    messages: List[str]         # All messages returned by the API
    message: str                # Primary message retured by the API
    reload_datatables: bool     # Whether to reload datatables
    reload: bool                # Whether to reload site


#
#   Main Class
#

class MCHost24API:
    def __init__(self, token: str = None):
        if token:
            self.auth = HTTPTokenAuth(token)
        else:
            self.auth = None
    
    def set_token(self, token: str) -> None:
        """Set API token 
        
        Args:
            token: The API token to set
        
        """
        self.auth = HTTPTokenAuth(token)
    
    def get_token(self, username: str, password: str, tfa: int = None) -> APIResponse:
        """Gets an API token from the API using a user's credentials
        
        Args:
            username: The username of the user to authenticate
            password: The password of the user to authenticate
            [tfa]: The 2FA code of the user, if required
        
        Returns:
            An API token that can be used to interact with the API
        """
        
        endpoint = "/token"
        payload = {
            "username": username,
            "password": password
        }

        if tfa is not None:
            payload["tfa"] = tfa
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("POST", endpoint, json=payload).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        # Try to parse into response object and catch malformed API request with special case
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        return response
    
    def logout(self) -> APIResponse:
        """Logout and invalidate the API token"""
        
        endpoint = "/logout"
        
        if self.auth is None:
            raise MCH24UnauthorizedError("No token is present to log out", endpoint)
        
        try:
            response = api_request("POST", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        return response