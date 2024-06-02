# MC-Host24 Python API

A Python Module that allows interacting with the [MC-Host24](https://mc-host24.de) REST API.

## Installation

The package can be installed by cloning the repository and executing the following command in the directory:

```sh
pip install .
```

## Usage

The module `mchost24.api` contains the dataclasses, types, etc. used by the API and the class `MCHost24API` can be used to interact with the REST API.
The class requires an API key for most of the functionality. This API key can be generated using the API key manager (see below).

## API Key Manager

By executing the module with the sub command `manage`, the API key manager can be opened:

```sh
python -m mchost24 manage
```

This manager allows the generation of new API keys using the user's credentials and the invalidation of existing API keys