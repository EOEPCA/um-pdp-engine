[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
![Build][build-shield]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/EOEPCA/um-pdp-engine">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">um-pdp-engine</h3>

  <p align="center">
    Policy Decision Point for EOEPCA project
    <br />
    <a href="https://eoepca.github.io/um-pdp-engine/"><strong>Explore the docs »</strong></a>
    <br />
    <a href="https://github.com/EOEPCA/um-pdp-engine/issues">Report Bug</a>
    ·
    <a href="https://github.com/EOEPCA/um-pdp-engine/issues">Request Feature</a>
  </p>
</p>

## Table of Contents

- [Table of Contents](#table-of-contents)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Usage & functionality](#usage--functionality)
- [Developer documentation](#developer-documentation)
  - [Demo functionality](#demo-functionality)
  - [Endpoints](#endpoints)
  - [Resources cache](#resources-cache)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)

<!-- ABOUT THE PROJECT -->

### Built With

- [Python](https://www.python.org//)
- [YAML](https://yaml.org/)
- [Travis CI](https://travis-ci.com/)
- [Docker](https://docker.com)
- [Kubernetes](https://kubernetes.io)

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.

- [Docker](https://www.docker.com/)
- [Python](https://www.python.org//)

### Installation

1. Get into EOEPCA's development environment

```sh
vagrant ssh
```

3. Clone the repo

```sh
git clone https://github.com/EOEPCA/um-pdp-engine.git
```

4. Change local directory

```sh
cd um-pep-engine
```
## Dependencies
The PDP is written and tested for python 3.6.9, and has all dependencies listed in src/requirements.txt

## Configuration

The PDP gets all its configuration (if the env variables are not used) from the file located under `config/config.json`.
The parameters that are accepted, and their meaning, are as follows:

- **auth_server_url**: complete url (with "https") of the Authorization server.
- **prefix**: "/path"-formatted string to indicate where the reverse proxy should listen. The proxy will catch any request that starts with that path. Default is "/pdp"
- **host**: Host for the proxy to listen on. For example, "0.0.0.0" will listen on all interfaces
- **port**: Port for the proxy to listen on. By default, **5567**. Keep in mind you will have to edit the docker file and/or kubernetes yaml file in order for all the prot forwarding to work.
- **check_ssl_certs**: Toggle on/off (bool) to check certificates in all requests. This should be forced to True in a production environment
- **debug_mode**: Toggle on/off (bool) a debug mode of Flask. In a production environment, this should be false.
- **client_id**: string indicating a client_id for an already registered and configured client. **This parameter is optional**. When not supplied, the PEP will generate a new client for itself and store it in this key inside the JSON.
- **client_secret**: string indicating the client secret for the client_id. **This parameter is optional**. When not supplied, the PEP will generate a new client for itself and store it in this key inside the JSON.

## Usage & functionality

Use directly from docker with
```sh
docker run --publish <configured-port>:<configured-port> <docker image>
```
Where **configured-port** is the port configured inside the config.json file inside the image. The default image is called **eoepca/um-pdp-engine:latest**.

If this is running in a development environment without proper DNS setup, add the following to your docker run command:
```sh
--add-host <auth-server-dns>:<your-ip>
```

When launched, the PDP will answer to all requests that start with the configured path.
The requests should be accompained by an "Authorization: Bearer <valid_RPT>" for all endpoints except for the de /validate

Examples, given the example values of:
- path configured: "/pdp"
- PDP is at pdp.domain.com/policy
- For Validate policies : "/policy/validate"

| Token | Request to PDP | PDP Action | PDP answer |
|-------|---------|------------|--------------|
| No RPT/OAuth token | pdp.domain.com | None (request does not get to PDP endpoint) | None (the PDP doesn't see this request) |
| No RPT/OAuth token and Valid data | pdp.domain.com/policy/validate with a json as data | Validates the policy access related to the json request | Return a response with Permit access |
| No RPT/OAuth token and Not valid data | pdp.domain.com/policy/validate with a json as data | Validates the policy access related to the json request | Return a response with Deny access |
| RPT/OAuth token + Policy information as data  | pdp.domain.com/policy/ | Register Policy in MongoDB | Policy_id for the policy just created |
| No RPT/OAuth token + Policy information as data | pdp.domain.com/policy/ | Register Policy in MongoDB | 401 |
| RPT/OAuth token + Policy information as data | pdp.domain.com/policy/<policy_id or ObjectId(policy_id)> | Performs the operations of Get/Update/Delete policy  | Get: Return the policy Update: "updated" or "no changes made"  Delete: 204 if exists|
| No RPT/OAuth token + Policy information as data | pdp.domain.com/policy/<policy_id or ObjectId(policy_id)> | Performs the operations of Get/Update/Delete policy | 401 |

## Developer documentation
The API will expose an endpoint to interact with the policies.
The main endpoints for the policy operations exposed by the API are now secured with OAuth/OIDC, it would accept both OAuth access_token and JWT id_token in order to authorize the user and both are expected on the header.
This check will retrieve the UUID for the user and insert it on the data model of the policy storage, so when any call is made against a policy, the API will double check if the UUID of the requester matches the one associated to the policy in order to operate against it.

--------

Testing and Demo for policies operations with Mongo:

The token can be generated by the oidc library.

For the endpoint:  <DOMAIN>/policy

  Register Policy (PUT/POST):

    curl -k -v -XPOST 'http://<DOMAIN>/policy/' -H 'Content-Type: application/json, Authorization: Bearer <OAuth access_token or JWT id_token>' -d '{"name":"NewPolicy","description":"Description for this new policy","config":{"resource_id":"6666666","rules":[{"AND":[{"EQUAL":{"user_name":"admin"}}]}]},"scopes":["oidc"]}'

This will return te policy_id for the policy just created (i.e: 5f32f236ea1bacfddd396e97)

For the endpoint: <DOMAIN>/policy/<policy_id or ObjectId(policy_id)>

  Update Policy (PUT/POST):

    curl -k -v -XPOST 'http://<DOMAIN>/policy/5f32f236ea1bacfddd396e97' -H 'Content-Type: application/json, Authorization: Bearer <OAuth access_token or JWT id_token>' -d '{"name":"NewPolicyChanged","description":"Description for this new policy changed","config":{"resource_id":"6666666","rules":[{"AND":[{"EQUAL":{"user_name":"admin"}}]}]},"scopes":["Authorized"]}'
    curl -k -v -XPUT 'http://<DOMAIN>/policy/ObjectId(5f32f236ea1bacfddd396e97)' -H 'Content-Type: application/json, Authorization: Bearer <OAuth access_token or JWT id_token>' -d '{"name":"NewPolicyChanged","description":"Description for this new policy changed","config":{"resource_id":"6666666","rules":[{"AND":[{"EQUAL":{"user_name":"admin"}}]}]},"scopes":["Authorized"]}'

  Get Policy (GET):

  By its _id:

    curl -k -v -XGET 'http://<DOMAIN>/policy/5f32f236ea1bacfddd396e97' -H 'Content-Type: application/json, Authorization: Bearer <token>'

  By its resource_id:

    curl -k -v -XGET 'http://<DOMAIN>/policy/5f339a1e8e8f28850cb2e6e7' -H 'Content-Type: application/json, Authorization: Bearer <token>' -d '{"resource_id": "6666666"'

  Delete Policy (DELETE):
  
    curl -k -v -XDELETE 'http://<DOMAIN>/policy/5f32f236ea1bacfddd396e97' -H 'Content-Type: application/json, Authorization: Bearer <token>'

--------

Testing and Demo to usage of XACML compatible policy language (Local Testing):

1. Install the python libraries

```sh
pip3 install -r src/requirements.txt
```

2. Run the PDP (A docker container with mongo should be running: `sudo docker run -p 27017:27017 -d mongo`)

```sh
python3  src/main.py
```

3. Run the unittest

```sh
python3 -m unittest src/um_pdp_test.py
```

### Test functionality

In order to test the PDP engine at the moment first you have reach this prerequisites:

- In gluu, go to Manage Custom Scripts, UMA RPT Policies, and disable the scim_access_policy
- In gluu, go to the UMA > Scopes section. Open up the SCIM Access scope, and add the open_policy to the Authorization Policies section

### Endpoints

The PDP uses the following endpoints from a "Well Known Handler", which parses the Auth server's "well-known" endpoints:

- TYPE_OIDC
- KEY_OIDC_USERINFO_ENDPOINT

## Roadmap

See the [open issues](https://github.com/EOEPCA/um-pdp-engine/issues) for a list of proposed features (and known issues).


## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

## Contact

[EOEPCA mailbox](eoepca.systemteam@telespazio.com)

Project Link: [https://github.com/EOEPCA/um-pdp-engine](https://github.com/EOEPCA/um-pdp-engine)

## Acknowledgements

- README.md is based on [this template](https://github.com/othneildrew/Best-README-Template) by [Othneil Drew](https://github.com/othneildrew).


[contributors-shield]: https://img.shields.io/github/contributors/EOEPCA/um-pdp-engine.svg?style=flat-square
[contributors-url]: https://github.com/EOEPCA/um-pdp-engine/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/EOEPCA/um-pdp-engine.svg?style=flat-square
[forks-url]: https://github.com/EOEPCA/um-pdp-engine/network/members
[stars-shield]: https://img.shields.io/github/stars/EOEPCA/um-pdp-engine.svg?style=flat-square
[stars-url]: https://github.com/EOEPCA/um-pdp-engine/stargazers
[issues-shield]: https://img.shields.io/github/issues/EOEPCA/um-pdp-engine.svg?style=flat-square
[issues-url]: https://github.com/EOEPCA/um-pdp-engine/issues
[license-shield]: https://img.shields.io/github/license/EOEPCA/um-pdp-engine.svg?style=flat-square
[license-url]: https://github.com/EOEPCA/um-pdp-engine/blob/master/LICENSE
[build-shield]: https://www.travis-ci.com/EOEPCA/um-pdp-engine.svg?branch=master
