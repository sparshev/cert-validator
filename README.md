# Cert Validator

This python3 script allow to scan the provided list of sites, check their validity and export the
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

Tested on: (2.7.17, 3.6.9)

## Usage

Just run the script and it will show the help screen:
```
$ ./CertValidator.py -h
```

### Example

* Run through file list with output to pems directory and sort the output
```
$ ./CertValidator.py -f test_list.lst -o pems -s
53d left - www.google.com:443
57d left - www.facebook.com:443
106d left - www.yahoo.com:443
203d left - www.apple.com:443
650d left - www.netflix.com:443

$ ls -alh pems
total 20K
drwxr-x--- 1 user user  222 Apr  2 22:10 .
drwxr-xr-x 1 user user  156 Apr  2 22:10 ..
-rw-r--r-- 1 user user 2.5K Apr  2 22:10 www.apple.com_443.pem
-rw-r--r-- 1 user user 2.2K Apr  2 22:10 www.facebook.com_443.pem
-rw-r--r-- 1 user user 1.3K Apr  2 22:10 www.google.com_443.pem
-rw-r--r-- 1 user user 2.8K Apr  2 22:10 www.netflix.com_443.pem
-rw-r--r-- 1 user user 2.5K Apr  2 22:10 www.yahoo.com_443.pem
```
* Run throught stdin list with output to pems2 dir and verbosity without sorting
```
$ echo "www.apple.com\nwww.google.com" | ./CertValidator.py -f - -o pems2 -v
DEBUG: SSL Context stats: {'x509': 0, 'x509_ca': 0, 'crl': 0}
DEBUG: SSL Context CA certs: []
DEBUG: SSL default verify paths: DefaultVerifyPaths(cafile=None, capath='/usr/lib/ssl/certs', openssl_cafile_env='SSL_CERT_FILE', openssl_cafile='/usr/lib/ssl/cert.pem', openssl_capath_env='SSL_CERT_DIR', openssl_capath='/usr/lib/ssl/certs')
203d - www.apple.com:443
53d - www.google.com:443

$ ls -alh pems2
total 8.0K
drwxr-x--- 1 user user   86 Apr  2 22:13 .
drwxr-xr-x 1 user user  150 Apr  2 22:13 ..
-rw-r--r-- 1 user user 2.5K Apr  2 22:13 www.apple.com_443.pem
-rw-r--r-- 1 user user 1.3K Apr  2 22:13 www.google.com_443.pem
```

## Script highlights

* Using built-in threading (GIL) due to ssl-request most of the time waiting for response
* Minimal number of dependencies to simplify direct running on the target system
* Reusability from another scripts by importing as a module

## TODO

* Streaming support
* Automation to check style and validate python code
* Unit tests
* Code coverage
* Automation for unit tests execution
* CI to execute automation on pull request and during merge

## License

Repository and it's content is covered by `Apache v2.0` - so anyone can use it without any concerns.
