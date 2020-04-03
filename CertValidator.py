#!/usr/bin/env python

'''CertValidator v1.0

Author: Sergei Parshev <sergei@parshev.net>
Description: Simple multithreaded script to validate the provided domains/IPs SSL/TLS certificates
'''

from __future__ import print_function

import os, sys, re
import argparse

import socket, ssl
from datetime import datetime
import bisect
import threading

try:
    import Queue as queue # Python 2
except ImportError:
    import queue # Python 3

def eprint(*args, **kwargs):
    '''Print to stderr'''
    print(*args, file=sys.stderr, **kwargs)

class CertValidator(object):
    '''Object to control the cert validating process'''

    # Allow only symbols allowed in standard
    _allowed_hostname = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

    # Datetime parse format to sort the certificates
    _dtformat = '%b %d %H:%M:%S %Y %Z'

    def __init__(self, args):
        '''Init object with provided array arguments'''
        # TODO: not the best interface to use from non-cli logic,
        # but unifies validation of variables and default settings
        parser = self.create_parser()

        self._cfg = self.parse_args(parser, args)

    def create_parser(self):
        '''Create parser and specify arguments'''
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('-f', '--file-list', dest='file_list',
                            help='set newline separated file list of domains/IPs '
                                 'or use "-" to read stdin')
        parser.add_argument('-v', '--verbose', action='count', default=0,
                            help='increase output verbosity')
        parser.add_argument('-p', '--port', type=int, default=443,
                            help='default port to use during connection')
        parser.add_argument('-t', '--threads-max', type=int, default=16, dest='threads_max',
                            help='set the max number of parallel threads')
        parser.add_argument('-c', '--ca',
                            help='pem file with custom CA to validate the certs')
        parser.add_argument('-n', '--names',
                            help='domains/IPs comma separated list to validate')
        parser.add_argument('-w', '--warnings', action='store_true',
                            help='only print certs with issues')
        parser.add_argument('-s', '--sort', action='store_true',
                            help='sort certificates by validation and expiration')
        parser.add_argument('-d', '--days', type=int,
                            help='warn when cert expires less then in number of days')
        parser.add_argument('-o', '--out-dir', dest='out_dir',
                            help='directory to store captured data files')
        parser.add_argument('--timeout', type=float, default=1.0,
                            help='connection timeout to get the certificate')
        return parser

    def parse_args(self, parser, args):
        '''Processing config arguments'''
        args = parser.parse_args(args)

        if not (args.file_list or args.names):
            eprint('ERROR: no names provided to validate, use -l or -n')
            parser.print_help()
            sys.exit(1)

        return args

    def validate_fqdn(self, hostname):
        '''Verify host string'''
        if len(hostname) > 255:
            return False
        if hostname[-1] == '.':
            hostname = hostname[:-1] # strip exactly one dot from the right, if present
        return all(self._allowed_hostname.match(x) for x in hostname.split('.'))

    def prepare_address(self, addr_str):
        '''Parse one string address to separated (host, port) address'''
        address = addr_str.split(':', 1)
        if len(address) == 1 or address[1].strip() == '':
            # Use default port if port is not set
            address = (address[0], self._cfg.port)
        else:
            # If port is set - validating
            try:
                address[1] = int(address[1])
            except ValueError:
                raise Exception('ERROR: Unable to parse address port "%s"' % addr_str)
            if address[1] < 1 or address[1] > 65535:
                raise Exception('ERROR: Unable to use address port "%s"' % addr_str)

        address = (address[0].strip(), address[1])
        if address[0] == '' or not self.validate_fqdn(address[0]):
            raise Exception('ERROR: Address host is invalid "%s"' % addr_str)

        return address

    def process(self):
        '''Run the data processing'''
        self.process_prepare()
        self.process_input()
        self.process_results()

    def process_prepare(self):
        '''Run the validation process as a separated thread'''
        self._queue_in = queue.Queue()
        self._queue_out = queue.Queue()

        # Set timeout for sockets
        socket.setdefaulttimeout(self._cfg.timeout)

        # Check the out directory
        if self._cfg.out_dir:
            if not os.path.isdir(self._cfg.out_dir):
                try:
                    os.makedirs(self._cfg.out_dir, 0o750)
                except IOError as e:
                    raise Exception('ERROR: Unable to create directory:', self._cfg.out_dir, e)
            if not os.access(self._cfg.out_dir, os.W_OK):
                raise Exception('ERROR: Unable to write to directory:', self._cfg.out_dir)

        # Preprocess names and put them to queue
        if self._cfg.names:
            for addr_str in self._cfg.names.split(','):
                self._queue_in.put(self.prepare_address(addr_str))

        # Prepare input file and retreive addresses
        if self._cfg.file_list:
            if self._cfg.file_list == '-':
                # Use stdin to retreive the list
                self._file_in = sys.stdin
            else:
                if not os.access(self._cfg.file_list, os.R_OK):
                    raise Exception('ERROR: Unable to read file:', self._cfg.file_list)
                # Use file to read data - the file also could be a filesocket
                self._file_in = open(self._cfg.file_list, 'r')

            for line in self._file_in:
                self._queue_in.put(self.prepare_address(line.rstrip()))

        # Create reusable SSL context, because the configs are the same
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self._ctx.verify_mode = ssl.CERT_REQUIRED
        self._ctx.check_hostname = True
        self._ctx.load_default_certs()

        if self._cfg.verbose:
            eprint('DEBUG: SSL Context stats:', self._ctx.cert_store_stats())
            eprint('DEBUG: SSL Context CA certs:', self._ctx.get_ca_certs())
            eprint('DEBUG: SSL default verify paths:', ssl.get_default_verify_paths())

    def process_input(self):
        '''Processing input data'''
        while True:
            try:
                address = self._queue_in.get(True, 0.1)
            except queue.Empty:
                break # TODO: For streaming need to check that the stream is over

            result = {
                'address': address,
                'cert_pem': None,
                'cert_data': None,
                'not_after': None,
                'errors': [],
            }

            try:
                # Get the server certificate in PEM and ensure host is ok

                # TODO: that will be better to decode the cert and show info for the user
                # but looks like it's hard without the additional (not-builtin) modules
                result['cert_pem'] = ssl.get_server_certificate(address)

                # Connect using socket to validate cert and get parsed cert
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = self._ctx.wrap_socket(sock, server_hostname=address[0])
                try:
                    ssl_sock.connect(address)
                    result['cert_data'] = ssl_sock.getpeercert()
                    result['not_after'] = datetime.strptime(
                            result['cert_data']['notAfter'], self._dtformat)
                except ssl.SSLError as e:
                    # In case the certificate is invalid
                    if self._cfg.verbose:
                        eprint('DEBUG: SSL error for address %s: %s', address, e)
                    result['errors'].append(e)
                finally:
                    ssl_sock.close()
            except IOError as e:
                # Catch timeout or dns resolution error
                if self._cfg.verbose:
                    eprint('DEBUG: Connection issue to', address, e)
                result['errors'].append(e)
            except Exception as e:
                if self._cfg.verbose:
                    eprint('DEBUG: Unknown exception during connection', address, e)
                result['errors'].append(e)

            self._queue_out.put(result)

    def process_results(self):
        '''Processing results data'''
        self._sort_id = []
        self._sort_data = {}
        while True:
            try:
                res = self._queue_out.get(True, 0.1)
            except queue.Empty:
                break # TODO: For streaming need to check that the stream is over

            if self._cfg.sort and not res['errors']:
                # Sort only valid results
                secs = int((res['not_after'] - datetime(1970, 1, 1)).total_seconds())
                bisect.insort(self._sort_id, secs)
                self._sort_data[secs] = res
            else:
                status = 'FAILURE' if res['errors'] else ('%dd' % (
                    res['not_after'] - datetime.now()).days)
                print('%s - %s:%d' % (status, res['address'][0], res['address'][1]))

            if res['cert_pem'] and self._cfg.out_dir:
                # Save pem file
                out_file = os.path.join(self._cfg.out_dir, '%s_%d.pem' % res['address'])
                with open(out_file, 'w') as f:
                    f.write(res['cert_pem'])

        # Print sorted data
        now = datetime.now()
        if self._cfg.sort:
            for i in self._sort_id:
                res = self._sort_data[i]
                diff = res['not_after'] - now
                print('%sd left - %s:%d' % (diff.days, res['address'][0], res['address'][1]))

    def wait(self):
        '''Wait until all the list will be processed'''
        pass


def main():
    '''Executing the validation process with cli arguments'''
    cv = CertValidator(sys.argv[1:])
    cv.process()
    cv.wait()

if __name__ == '__main__':
    main()
