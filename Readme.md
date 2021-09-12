# Server for Project Coconut

[![CI](https://github.com/jaeha-choi/Proj_Coconut_Server/actions/workflows/CI.yml/badge.svg)](https://github.com/jaeha-choi/Proj_Coconut_Server/actions/workflows/CI.yml)
[![codecov](https://codecov.io/gh/jaeha-choi/Proj_Coconut_Server/branch/master/graph/badge.svg?token=8JIUNFLL8N)](https://codecov.io/gh/jaeha-choi/Proj_Coconut_Server)

### What is Project Coconut

An open-source, cross-platform solution to share files between devices.

## Installation

TODO: Update URL once the executable file is uploaded

1. Change working directory to desired installation directory
    - `cd /desired/path/`
2. Download the executable file
    - Using curl: `curl -OJ *url*`
    - Using wget: `wget *url*`
3. Make it executable
    - `chmod +x *file_name*`
4. Create a folder and change the working directory
    - `mkdir -p data/cert && cd data/cert`
5. Generate an RSA key
    - `openssl genrsa -out server.key 4096`
6. To generate a self-signed certificate for a testing purpose, using the following command:
    - `openssl req -new -x509 -sha256 -key server.key -out server.crt`
7. Change the working directory to main directory
    - `cd ../..`
8. Start the server
    - `./coconut_server *optional_arguments*`

## Build

TODO: Update build

## Arguments

TODO: Update arguments