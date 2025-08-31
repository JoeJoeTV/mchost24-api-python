import requests
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from typing import Union, List
from enum import Enum
import json
from urllib.parse import urljoin
import pprint
import logging
import datetime
import pytimeparse2

#
#   Constants
#

VERSION = "1.0.0"
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

def stats_time_decode(original_value: list[str]) -> list[datetime.time | datetime.datetime]:
    """Decodes the list of time/date strings used by the rootserver statistics to datetime.datetime and time objects"""
    
    decoded_value= []
    
    for timestr in original_value:
        try:
            decoded_value.append(datetime.datetime.strptime(timestr, "%d.%m.%y %H:%M"))
        except ValueError:
            t = datetime.datetime.strptime(timestr, "%H:%M:%S")
            decoded_value.append(datetime.time(hour=t.hour, minute=t.minute, second=t.second))
    
    return decoded_value

def stats_time_encode(original_value: list[datetime.time | datetime.datetime]) -> list[str]:
    """Encodes lists of datetime.datetime and time objects into the format used by the rootserver statistics"""
    
    decoded_value= []
    
    for dt in original_value:
        if isinstance(dt, datetime.datetime):
            decoded_value.append(dt.strftime("%d.%m.%y %H:%M"))
        elif isinstance(dt, time):
            decoded_value.append(dt.strftime("%H:%M:%S"))
        else:
            raise ValueError(f"Value '{str(dt)}' is not a datetime.datetime or time object!")
    
    return decoded_value

def runtime_timespan_decode(original_value: str) -> datetime.timedelta:
    """Decodes a timespan in natural language to a timedelta object"""
    
    pytimeparse2.disable_dateutil()
    secs = pytimeparse2.parse(original_value, as_timedelta=False)
    return datetime.timedelta(seconds=secs)

def runtime_timespan_encode(original_value: datetime.timedelta) -> str:
    """Encodes a timespan given as a timedelta object into natrual language"""
    
    # See https://stackoverflow.com/a/13756038/11286087
    PERIODS = [
        ('year',    60*60*24*365),
        ('day',     60*60*24)
    ]
    
    secs = int(original_value.total_seconds())
    
    for period_name, period_seconds in PERIODS:
        if secs >= period_seconds:
            period_value, secs = divmod(secs, period_seconds)
            has_s = 's' if period_value > 1 else ''
            return f"{str(period_value)} {period_name}{has_s}"

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
class TimeFrame(Enum):
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"
class TicketState(Enum):
    CLOSED = "CLOSED"
    OPENED = "OPENED"
class SpecialUser(Enum):
    SYSTEM = "SYSTEM"
class DiscountApplyType(Enum):
    NEW = "NEW"
    RENEW = "RENEW"
    UPGRADE = "UPGRADE"

class DiscountType(Enum):
    PERCENT = "PERCENT"
    LIMITED_OFFER = "LIMITED_OFFER"

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
    service_ordered_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp)) # Time at which the product was ordered
    expire_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))          # Time at which the product should expire
    expired_at: datetime.datetime | None = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))  # Time at which the product expired
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
    time: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp)) # Timestamp with nanoseconds
    message: str
    file: str       # Backup archive file name
    ftp: str        # FTP address and port
    type: str


@dataclass_json
@dataclass
class APIDataDomain:
    id: int                         # The MC-HOST24 database id
    service_id: int                 # The MC-HOST24 service id
    service_ordered_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))   # Time at which the product was ordered
    expire_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))            # Time at which the product should expire
    expired_at: datetime.datetime | None = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))    # Time at which the product expired
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

@dataclass_json
@dataclass
class RootServerAddress:
    ip: str             # IPv4 address assigned to server
    rdns: str | None    # Reverse DNS entry for IP address

@dataclass_json
@dataclass
class APIDataRootServer:
    id: int                             # The MC-HOST24 database id
    service_id: int                     # The MC-HOST24 service id
    service_id: int                     # The MC-HOST24 service id
    service_ordered_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))   # Time at which the product was ordered
    expire_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))            # Time at which the product should expire
    expired_at: datetime.datetime | None = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))    # Time at which the product expired
    product_name: str | None            # The product name
    cores: int                          # Amout of cores assigned to the rootserver
    memory: int                         # Rootserver mermory in Mebibytes
    disk_size: int                      # Rootserver disk size in Gibibytes
    installed: bool                     # Whether the server is installed or not
    traffic: int                        # Maximum value in gigabytes that the server can use in terms of traffic (can be increased via support if exceeded)
    curr_traffic: float                 # Current traffic value in gigabytes
    online: bool                        # Whether the server is online
    cpu_pc: int                         # Current cpu usage in percentage
    curr_memory: int                    # Current memory usage in gibibytes
    addresses: list[RootServerAddress]  # The addresses assigned to the rootserver

@dataclass_json
@dataclass
class APIDataRootServerBackup:
    id: int         # The MC-HOST24 database id
    created_at: datetime.datetime = field(metadata=config(encoder=datetime.datetime.timestamp, decoder=datetime.datetime.fromtimestamp))   # Time at which the backup was created
    finished: bool  # Whether the backups is finished or still in progress

@dataclass_json
@dataclass
class APIDataRootServerVNC:
    url: str    # The URL to the VNC web access

@dataclass_json
@dataclass
class APIDataStats:
    time: list[datetime.datetime | datetime.time] = field(metadata=config(encoder=stats_time_encode, decoder=stats_time_decode))
    cpu: list[float]
    mem: list[float]
    diskread: list[float]
    diskwrite: list[float]
    netin: list[float]
    netout: list[float]
    maxmem: float

@dataclass_json
@dataclass
class APIDataProfile:
    id: int                     # MC-HOST24 database id
    name: str                   # Username of the account
    rname: str                  # Real name of the account
    email: str                  # Email of the account
    money: float                # Current balance of the account
    donation_url: str | None    # Donation URL of the account, if set

@dataclass_json
@dataclass
class TicketAnswer:
    id: int                             # Database id of ticket answer
    ticket_id: int                      # Database id of reference ticket
    msg: str                            # Content of answer
    user_id: int | None | SpecialUser   # User id who sent the reply
    col_id: int | None                  # ID of the collaborator who sent the reply
    created_at: datetime.datetime | None = field(metadata=config(encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))
    updated_at: datetime.datetime | None = field(metadata=config(encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))
    deleted_at: datetime.datetime | None = field(metadata=config(encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))

@dataclass_json
@dataclass
class APIDataTicket:
    id: int                         # Ticket id from Database
    user_id: int                    # User id of the opener
    col_id: int | None              # ID of the collaborator
    subject: str = field(metadata=config(field_name="betr"))    # Subject of the ticket
    msg: str                        # Content of the ticket
    state: TicketState              # State of the ticket
    server_id: int | None           # Server id mentioned in the ticket
    service_id: int | None          # Service id mentioned in the ticket
    ticket_category_id: str | None  # Id of the ticket category
    answers: list[TicketAnswer]     # List of answers to the ticket
    pinned: bool                    # Whether the ticket is pinned of not
    created_at: datetime.datetime | None = field(metadata=config(encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))
    #NOTE: The field returned by the API is called 'updated_ad' which is probably a typo
    updated_at: datetime.datetime | None = field(metadata=config(field_name="updated_ad", encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))

@dataclass_json
@dataclass
class Discount:
    id: int                     # Database id of discount
    discount_percent: int       # Percentage value of the discount
    type: DiscountApplyType     # Discount application type
    start_at: datetime.datetime = field(metadata=config(encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))
    end_at: datetime.datetime = field(metadata=config(encoder=lambda x: datetime.datetime.strftime(x, "%Y-%m-%dT%H:%M:%S.%fZ"), decoder=lambda x: datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")))
    discount_type: DiscountType # Discount type

@dataclass_json
@dataclass
class RuntimePrice:
    runtime: datetime.timedelta = field(metadata=config(encoder=runtime_timespan_encode, decoder=runtime_timespan_decode))  # Renew period
    price: float    # Renew price for period

@dataclass_json
@dataclass
class APIDataServiceRenew:
    runtimes: list[RuntimePrice]    # Available runtimes with corresponding prices
    discount: Discount | None       # Applicable discount

# Type definitions
APIDataAvailableRecords = dict[str, str]
APIData = APIDataToken | APIDataMinecraftServer | APIDataMinecraftServerBackup | APIDataDomain | APIDataDomainRecord | APIDataDomainInfo | APIDataAvailableRecords | APIDataRootServer | APIDataRootServerBackup | APIDataRootServerVNC | APIDataStats | APIDataProfile | APIDataTicket | APIDataServiceRenew

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
    
    #TODO: Abstract copy-pasted part of functions into common function
    
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
            "email": email,
            "password": password,
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
    
    def delete_domain_email(self, id: int, email_id: int) -> APIResponse:
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
    
    #
    #   Rootserver
    #
    
    def get_rootservers(self) -> APIResponse:
        """Get a list of all Rootserver"""
        
        endpoint = "/vserver"

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
    
    def get_rootserver_status(self, id: int) -> APIResponse:
        """Get the status of a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/status"

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

    def start_rootserver(self, id: int) -> APIResponse:
        """Starts a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/start"

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

    def shutdown_rootserver(self, id: int) -> APIResponse:
        """Shuts down a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/shutdown"

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

    def stop_rootserver(self, id: int) -> APIResponse:
        """Stops a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/stop"

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

    def restart_rootserver(self, id: int) -> APIResponse:
        """Restarts a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/restart"

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
        
    def get_rootserver_backups(self, id: int) -> APIResponse:
        """Get a list of all backups for a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/backups"

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

    def create_rootserver_backup(self, id: int) -> APIResponse:
        """Creates a new backup for a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/backups"

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
    
    def restore_rootserver_backup(self, id: int, backup_id: int) -> APIResponse:
        """Restores a Rootserver to an existing backup
        
        Args:
            id: The id of the Rootserver
            backup_id: The id of the Rootserver backup to restore
        """
        
        endpoint = f"/vserver/{str(id)}/restore/{str(backup_id)}"

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
    
    def delete_rootserver_backup(self, id: int, backup_id: int) -> APIResponse:
        """Deletes an existing Rootserver backup
        
        Args:
            id: The id of the Rootserver
            backup_id: The id of the Rootserver backup to delete
        """
        
        endpoint = f"/vserver/{str(id)}/backup/{str(backup_id)}/delete"

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
    
    def get_rootserver_vnc(self, id: int) -> APIResponse:
        """Gets a URL to the VNC web access of a Rootserver
        
        Args:
            id: The id of the Rootserver
        """
        
        endpoint = f"/vserver/{str(id)}/vnc"

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
    
    def get_rootserver_stats(self, id: int, tf: TimeFrame) -> APIResponse:
        """Gets various Rootserver stats given the timeframe
        
        Args:
            id: The id of the Rootserver
            tf: The timeframe to get the data for
        """
        
        endpoint = f"/vserver/{str(id)}/rrddata"
        payload = {
            "tf": tf.value
        }
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("GET", endpoint, json=payload, auth=self.auth).json()
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
    
    #
    #   User
    #
    
    def get_profile(self) -> APIResponse:
        """Gets profile information about the authenticated user"""
        
        endpoint = "/profile"
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("GET", endpoint, auth=self.auth).json()
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
    
    #
    #   Ticketsystem
    #
    
    def get_ticketsystem_info(self) -> None:
        """Gets information about the ticketsystem"""
        
        #TODO: Implement
        # Currently not aupported as the API response does not follow the schema at all
        
        raise MCHost24APIError("The /support/tickets/info endpoint is currently not supported")
    
    def get_support_tickets(self) -> APIResponse:
        """Get a list of all support tickets"""
        
        endpoint = "/support/tickets"

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
    
    def create_support_ticket(self, subject: str, text: str, service_id: int, category_id: int) -> APIResponse:
        """Creates a new support ticket
        
        Args:
            subject: The subject line of the support ticket
            text: The text content of the support ticket
            service_id: The service ID to link the ticket to
            category_id: The category ID of the support ticket
        """
        
        endpoint = "/support/tickets"
        payload = {
            "betr": subject,
            "text": text,
            "service": service_id,
            "ticket_category_id": category_id
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
    
    def get_support_tickets(self, id: int) -> APIResponse:
        """Gets information about a support ticket with the specified ID"""
        
        endpoint = f"/support/tickets/{str(id)}"

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
    
    def reply_to_support_ticket(self, id: int, text: str) -> APIResponse:
        """Sends reply to a support ticket
        
        Args:
            id: The ID of the support ticket to send a reply to
            text: The text to send as a reply to the support ticket
        """
        
        endpoint = f"/support/tickets/{str(id)}/reply"
        payload = {
            "reply": text
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
    
    def reopen_support_ticket(self, id: int) -> APIResponse:
        """Reopens a closed support ticket
        
        Args:
            id: The ID of the support ticket to reopen
        """
        
        endpoint = f"/support/tickets/{str(id)}/reopen"
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("POST", endpoint, auth=self.auth).json()
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
    
    def close_support_ticket(self, id: int) -> APIResponse:
        """Closes an open support ticket
        
        Args:
            id: The ID of the support ticket to close
        """
        
        endpoint = f"/support/tickets/{str(id)}/close"
        
        # Try to perform request and decode JSON response. Don't yet work on the JSON response.
        try:
            response = api_request("POST", endpoint, auth=self.auth).json()
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
    
    #
    #   Service
    #
    
    def get_service_renew_price(self, id: int) -> APIResponse:
        """Gets the renew price for a service
        
        Args:
            id: The ID of the service to get the price for
        """
        
        endpoint = f"/service/{str(id)}/price"

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
    
    def renew_service(self, id: int, runtime: datetime.timedelta) -> APIResponse:
        """Renews a service for a given runtime
        
        Args:
            id: The ID of the service to renew
            runtime: The runtime to renew the service for. Has to be one of the available runtimes
        """
        
        endpoint = f"/service/{str(id)}/renew"
        payload = {
            "runtime": runtime_timespan_encode(runtime)
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