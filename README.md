# Cert Validator

[![CircleCI](https://circleci.com/gh/sparshev/cert-validator/tree/master.svg?style=shield)](https://circleci.com/gh/sparshev/cert-validator)

This python2/3 script allow to scan the provided list of sites, check their validity and export the
captured certificates to file/s.

Also the script:
* Allow to use custom CA certificates
* Warn only if certificate is invalid or soon will be expired

## Why?

I got 24h to prepare the python script with the next requirements:
```
Scan through a list of websites, capture SSL Server Certificate
security details, sort Certificates data as per their validity,
and export data file.
```

Started: Thu Apr 2 13:27:06 2020 -0700

## Requirements

* Python >= 2.7.9 or 3.4.3

## Script highlights

* Using built-in threading (GIL) due to ssl-request most of the time waiting for response
* Minimal number of dependencies to simplify direct running on the target system
* Reusability from another scripts by importing as a module
* Streaming support
* Automation to check style and validate python code
* CI to execute automation on pull request and on master change
* Unit tests & CI automation

## TODO

* Code coverage

## Usage

Just run the script and it will show the help screen:
```
$ ./CertValidator.py -h
usage: CertValidator.py [-h] [-f FILE_LIST] [-v] [-p PORT] [-t THREADS_MAX]
                        [-n NAMES] [-s] [-o OUT_DIR] [--timeout TIMEOUT]
                        [-c CA] [--hostname-check] [-d DAYS] [-w]

CertValidator v1.0 Author: Sergei Parshev <sergei@parshev.net> Description:
Simple multithreaded script to validate the provided domains/IPs SSL/TLS
certificates

optional arguments:
  -h, --help            show this help message and exit
  -f FILE_LIST, --file-list FILE_LIST
                        set newline separated file list of domains/IPs or use
                        "-" to read stdin
  -v, --verbose         increase output verbosity
  -p PORT, --port PORT  default port to use during connection
  -t THREADS_MAX, --threads-max THREADS_MAX
                        set the max number of parallel threads
  -n NAMES, --names NAMES
                        domains/IPs comma separated list to validate
  -s, --sort            sort certificates by validation and expiration
  -o OUT_DIR, --out-dir OUT_DIR
                        directory to store captured data files
  --timeout TIMEOUT     connection timeout to get the certificate
  -c CA, --ca CA        cafile or capath with custom CA to validate the certs
  --hostname-check      check hostname to be set correctly
  -d DAYS, --days DAYS  warn when cert expires less then in number of days
                        (TODO)
  -w, --warnings        only print certs with issues (TODO)
```

### Example

* Run through file list with output to pems directory and sort the output
    ```
    $ ./CertValidator.py -f test_list.lst -o pems -s
    45d left - www.wix.com:443
    53d left - www.google.com:443
    57d left - www.facebook.com:443
    106d left - www.yahoo.com:443
    178d left - myspace.com:443
    186d left - www.wikipedia.org:443
    203d left - www.apple.com:443
    650d left - www.netflix.com:443

    $ ls -alh pems
    total 32K
    drwxr-x--- 1 user user  348 Apr  3 01:23 .
    drwxr-xr-x 1 user user  156 Apr  3 01:23 ..
    -rw-r--r-- 1 user user 2.4K Apr  3 01:23 myspace.com_443.pem
    -rw-r--r-- 1 user user 2.5K Apr  3 01:23 www.apple.com_443.pem
    -rw-r--r-- 1 user user 2.2K Apr  3 01:23 www.facebook.com_443.pem
    -rw-r--r-- 1 user user 1.7K Apr  3 01:23 www.google.com_443.pem
    -rw-r--r-- 1 user user 2.8K Apr  3 01:23 www.netflix.com_443.pem
    -rw-r--r-- 1 user user 2.9K Apr  3 01:23 www.wikipedia.org_443.pem
    -rw-r--r-- 1 user user 2.1K Apr  3 01:23 www.wix.com_443.pem
    -rw-r--r-- 1 user user 2.5K Apr  3 01:23 www.yahoo.com_443.pem
    ```
* Run throught stdin list with output to pems2 dir and verbosity without sorting
    ```
    $ echo "www.apple.com\nwww.google.com" | ./CertValidator.py -f - -o pems2 -v
    DEBUG: Running process prepare
    DEBUG: SSL Context stats: {'x509': 0, 'x509_ca': 0, 'crl': 0}
    DEBUG: SSL Context CA certs: []
    DEBUG: SSL default verify paths: DefaultVerifyPaths(cafile=None, capath='/usr/lib/ssl/certs', openssl_cafile_env='SSL_CERT_FILE', openssl_cafile='/usr/lib/ssl/cert.pem', openssl_capath_env='SSL_CERT_DIR', openssl_capath='/usr/lib/ssl/certs')
    DEBUG: Running process feed
    DEBUG: End process feed
    DEBUG: Running process result
    53d - www.google.com:443
    203d - www.apple.com:443
    DEBUG: End process result

    $ ls -alh pems2
    total 8.0K
    drwxr-x--- 1 user user   86 Apr  3 01:23 .
    drwxr-xr-x 1 user user  166 Apr  3 01:23 ..
    -rw-r--r-- 1 user user 2.5K Apr  3 01:23 www.apple.com_443.pem
    -rw-r--r-- 1 user user 1.7K Apr  3 01:23 www.google.com_443.pem
    ```

## Testing

* Clone the repo
    ```
    $ git clone https://github.com/sparshev/cert-validator.git
    ```

### Docker

* Run tests in docker
    ```
    $ docker run -it --rm -v "${PWD}/cert-validator:/home/user/project:ro" python:2.7-alpine /home/user/project/test.sh
    $ docker run -it --rm -v "${PWD}/cert-validator:/home/user/project:ro" python:3-alpine /home/user/project/test.sh
    ```

### VENV

* Create venv and activate it
    ```
    $ python -m venv .venv
    $ . .venv/bin/activate
    ```
* Run tests
    ```
    $ ./test.sh
    ```

### SimpleHTTPSTest

* Go to test dir:
    ```
    $ cd tools
    ```
* Generate openssl ca & certs:
    ```
    $ openssl req -newkey rsa:4096 -nodes -keyout ca.key -x509 -days 1024 -sha256 -out ca.crt -subj "/C=US/ST=N/L=N/O=N/OU=N/CN=test-ca"
    $ openssl req -newkey rsa:4096 -nodes -keyout "key.pem" -sha256 -subj "/C=US/ST=N/L=N/O=N/OU=N/CN=test" -reqexts SAN -extensions SAN -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=IP:0.0.0.0\n")) -out "csr.csr"
    $ openssl x509 -req -in "csr.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -extensions SAN -extfile <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=IP:0.0.0.0\n")) -out "cert.pem" -days 512 -sha256
    ```
* Run the test https server:
    ```
    $ python https_server.py
    ```
* Execute CertValidator against 0.0.0.0:4443
    ```
    $ echo "0.0.0.0:4443" | ../CertValidator.py -f - -o ../pems3 -v -s -c ca.crt
    DEBUG: Running process prepare
    DEBUG: SSL Context stats: {'x509': 1, 'x509_ca': 1, 'crl': 0}
    DEBUG: SSL Context CA certs: [{'notBefore': u'Apr  3 07:46:30 2020 GMT', 'serialNumber': u'427427EA49DB3C49275745C14AC929B909A52663', 'notAfter': 'Jan 22 07:46:30 2023 GMT', 'version': 3L, 'subject': ((('countryName', u'US'),), (('stateOrProvinceName', u'N'),), (('localityName', u'N'),), (('organizationName', u'N'),), (('organizationalUnitName', u'N'),), (('commonName', u'test-ca'),)), 'issuer': ((('countryName', u'US'),), (('stateOrProvinceName', u'N'),), (('localityName', u'N'),), (('organizationName', u'N'),), (('organizationalUnitName', u'N'),), (('commonName', u'test-ca'),))}]
    DEBUG: SSL default verify paths: DefaultVerifyPaths(cafile=None, capath='/usr/lib/ssl/certs', openssl_cafile_env='SSL_CERT_FILE', openssl_cafile='/usr/lib/ssl/cert.pem', openssl_capath_env='SSL_CERT_DIR', openssl_capath='/usr/lib/ssl/certs')
    DEBUG: Running process feed
    DEBUG: End process feed
    DEBUG: Running process result
    512d left - 0.0.0.0:4443
    DEBUG: End process result
    ```

## License

Repository and it's content is covered by `Apache v2.0` - so anyone can use it without any concerns.
