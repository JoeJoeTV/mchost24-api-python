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

class MCH24ObjectNotFoundError(MCHost24APIError):
    """The requested object could not be found"""
    
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
        except Exception as e:
            raise MCHost24APIError("Error while parsing 404 response") from e
            
        if "resource not found" in resjson["message"]:
            raise MCH24UnknownEndpointError(endpoint)
        elif "No query results for model" in resjson["message"]:
            raise MCH24ObjectNotFoundError(resjson["message"], endpoint)
        else:
            return response
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
    response["success"] = response.get("success", False)
    
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

def api_request_decoder(origin_value: dict | list, dataclass_types: list[type]):
    """Deconder function to use with a @dataclass_json to fix importing unions of lists of unions recursively"""
    decoded_value = None
    
    if type(origin_value) is dict:
        # If origin value is a dict, we can directly decode it using the dataclass
        
        for dc in dataclass_types:
            try:
                decoded_value = dc.from_dict(origin_value)
                break
            except Exception as e:
                continue
    elif type(origin_value) is list:
        # If origin value is a list, we have to iterate over the elements and decode each one
        
        for dc in dataclass_types:
            try:
                value_list = []
                for e in origin_value:
                    value_list.append(dc.from_dict(e))
                decoded_value = value_list
                break
            except Exception as e:
                continue
    else:
        raise TypeError("'origin_value' either has to be a dict or a list!")
    
    # If none of the dataclasses matched, we simply return the original value
    if decoded_value is None:
        decoded_value = origin_value
    
    return decoded_value

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

class MinecraftServerBackupStatus(Enum):
    """Enum representing the status of a Minecraft Server backup"""
    DONE = "done"
    RUNNING = "running"

class DomainRecordType(Enum):
    """Enum representing the possible types of domain record usable in the API"""
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    SRV = "SRV"
    TXT = "TXT"
    CAA = "CAA"
    HTTP_F = "HTTP_F"
    HTTPS_F = "HTTPS_F"
    HTTP_H = "HTTP_H"
    HTTPS_H = "HTTPS_H"

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
class APIDataToken:
    api_token: str  # API Token to be used for authentication


@dataclass_json
@dataclass
class APIDataMinecraftServer:
    id: int                         # The MC-HOST24 database id
    service_id: int                 # The MC-HOST24 service id
    service_ordered_at: datetime = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp)) # Time at which the product was ordered
    expire_at: datetime = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp))          # Time at which the product should expire
    expired_at: datetime | None = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp))  # Time at which the product expired
    product_name: str | None        # The product name
    multicraft_id: int              # The multicraft panel id
    address: str                    # The ipv4 address of the minecraft server with port
    memory: int                     # Memory in Mebibyte
    online: bool                    # Current status of minecraft server
    players_online: int             # Current online players on minecraft server
    players_max: int                # Maximal online players on minecraft server
    cpu_usage: int                  # Current cpu usage of minecraft-server in percentage
    mem_usage: int                  # Current memory usage of minecraft-server in percentage

@dataclass_json
@dataclass
class APIDataMinecraftServerBackup:
    status: MinecraftServerBackupStatus # Current status of backup
    time: datetime = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp)) # Timestamp with nanoseconds
    message: str
    file: str       # Backup archive file name
    ftp: str        # FTP address and port
    type: str


@dataclass_json
@dataclass
class APIDataDomain:
    id: int                         # The MC-HOST24 database id
    service_id: int                 # The MC-HOST24 service id
    service_ordered_at: datetime = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp)) # Time at which the product was ordered
    expire_at: datetime = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp))   # Time at which the product should expire
    expired_at: datetime | None = field(metadata=config(encoder=datetime.timestamp, decoder=datetime.fromtimestamp))         # Time at which the product expired
    sld: str                        # The second level domain name
    tld: str                        # The top level domain name

@dataclass_json
@dataclass
class APIDataDomainRecord:
    id: int                 # Id of domain record
    sld: str                # SLD better known as subdomain
    type: DomainRecordType  # The type of the record
    target: str             # Target IP or TXT content etc.

@dataclass_json
@dataclass
class APIDataDomainInfo:
    domain: APIDataDomain               # Information about the domain
    records: list[APIDataDomainRecord]  # The DNS records of the domain
    # emails: APIDataDomain             # (Seemingly unused) Information about the registered emails for the domain

# Type definitions
APIDataAvailableRecords = dict[str, str]
APIData = APIDataToken | APIDataMinecraftServer | APIDataMinecraftServerBackup | APIDataDomain | APIDataDomainRecord | APIDataDomainInfo | APIDataAvailableRecords

@dataclass_json
@dataclass
class APIResponse:
    """ Data class representing an API response """
    data: APIData | list[APIData] = field(metadata=config(decoder=lambda x: api_request_decoder(x, list(APIData.__args__))))    # Data returned by the API
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
    
    #
    #   Authentication
    #
    
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
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
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
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response

    #
    #   Minecraft Server
    #
    
    def get_minecraft_servers(self) -> APIResponse:
        """Get a list of all minecraft servers"""
        
        endpoint = "/minecraftServer"

        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response

    def get_minecraft_server_status(self, id: int) -> APIResponse:
        """Gets the status of a single Minecraft server
        
        Args:
            id: The id of the Minecraft Server
        """
        
        endpoint = f"/minecraftServer/{str(id)}/status"

        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response

    def start_minecraft_server(self, id: int) -> APIResponse:
        """Starts a Minecraft server
        
        Args:
            id: The id of the Minecraft Server
        """
        
        endpoint = f"/minecraftServer/{str(id)}/start"

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
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response

    def stop_minecraft_server(self, id: int) -> APIResponse:
        """Stops a Minecraft server
        
        Args:
            id: The id of the Minecraft Server
        """
        
        endpoint = f"/minecraftServer/{str(id)}/stop"

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
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response

    def restart_minecraft_server(self, id: int) -> APIResponse:
        """Restarts a Minecraft server
        
        Args:
            id: The id of the Minecraft Server
        """
        
        endpoint = f"/minecraftServer/{str(id)}/restart"

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
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def get_minecraft_server_backups(self, id: int) -> APIResponse:
        """Get a list of all backups for a Minecraft server
        
        Args:
            id: The id of the Minecraft Server
        """
        
        endpoint = f"/minecraftServer/{str(id)}/backups"

        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    

    def backup_minecraft_server(self, id: int) -> APIResponse:
        """Starts a new Minecraft server backup
        
        Args:
            id: The id of the Minecraft Server
        """
        
        endpoint = f"/minecraftServer/{str(id)}/backups"

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
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    #
    #   Domain
    #
    
    def get_domains(self) -> APIResponse:
        """Get a list of all domains"""
        
        endpoint = "/domain"

        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def get_available_domain_records(self) -> APIResponse:
        """Get a list of available DNS record types"""
        
        endpoint = "/domain/availableRecords"

        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def get_domain_info(self, id: int) -> APIResponse:
        """Get additional information about a domain
        
        Args:
            id: The id of the Domain
        """
        
        endpoint = f"/domain/{str(id)}/info"

        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def create_domain_dns_record(self, id: int, sld: str, type: DomainRecordType, target: str) -> APIResponse:
        """Creates a new DNS record for the specified domain
        
        Args:
            id: The id of the Domain to create the record for
            sld: The subdomain for the record
            type: The type of record to create
            target: The target that the record points to
        """
        
        endpoint = f"/domain/{str(id)}/dns"
        payload = {
            "sld": sld,
            "type": type.value,
            "target": target
        }
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("POST", endpoint, json=payload, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        # Try to parse into response object and catch malformed API request with special case
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def delete_domain_dns_record(self, id: int, record_id: int) -> APIResponse:
        """Deletes an existing DNS record
        
        Args:
            id: The id of the Domain to delete the record from
            record_id: The id of the record to delete
        """
        
        endpoint = f"/domain/{str(id)}/dns/{str(record_id)}"
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("DELETE", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        # Try to parse into response object and catch malformed API request with special case
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def create_domain_email(self, id: int, email: str, password: str) -> APIResponse:
        """Creates a new EMail account for the specified domain
        
        Args:
            id: The id of the Domain to create the EMail account for
            email: The email username for the new account
            password: The password for the new account
        """
        
        endpoint = f"/domain/{str(id)}/email"
        payload = {
            "email": sld,
            "password": type.value,
        }
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("POST", endpoint, json=payload, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        # Try to parse into response object and catch malformed API request with special case
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response
    
    def delete_domain_dns_record(self, id: int, email_id: int) -> APIResponse:
        """Deletes an existing EMail account
        
        Args:
            id: The id of the Domain to delete the record from
            email_id: The id of the EMail account to delete
        """
        
        endpoint = f"/domain/{str(id)}/email/{str(email_id)}"
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("DELETE", endpoint, auth=self.auth).json()
        except (requests.RequestException) as e:
            raise MCHost24APIError("Error during API request", endpoint) from e
        
        # Try to parse into response object and catch malformed API request with special case
        try:
            response = APIResponse.from_dict(response)
        except KeyError as e:
            response = APIResponse.from_dict(fix_api_response(response))
        
        if response.status == APIResponseStatus.UNAUTHORIZED:
            raise MCH24UnauthorizedError(endpoint=endpoint)
        
        if response.status == APIResponseStatus.ERROR:
            raise MCHost24APIError("API raised error: " + response.message, endpoint)
        
        return response