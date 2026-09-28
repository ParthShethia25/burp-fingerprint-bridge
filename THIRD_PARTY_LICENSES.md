# Third-party software

The distributable JAR includes [Gson 2.13.1](https://github.com/google/gson), licensed
under Apache-2.0. The license text is available at
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

The Python worker installs these packages into a local virtual environment:

| Package | Version | License |
| --- | --- | --- |
| [curl-cffi](https://github.com/lexiforest/curl_cffi) | 0.16.2 | MIT |
| [FastAPI](https://github.com/fastapi/fastapi) | 0.126.0 | MIT |
| [Uvicorn](https://github.com/encode/uvicorn) | 0.38.0 | BSD-3-Clause |
| [Pydantic](https://github.com/pydantic/pydantic) | 2.13.4 | MIT |

Burp's [Montoya API](https://github.com/PortSwigger/burp-extensions-montoya-api)
is a compile-only dependency and is supplied by Burp at runtime.
Transitive dependency notices are included in each package's distribution.
