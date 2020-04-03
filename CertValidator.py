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

        self._workers = []

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
        parser.add_argument('-n', '--names',
                            help='domains/IPs comma separated list to validate')
        parser.add_argument('-s', '--sort', action='store_true',
                            help='sort certificates by validation and expiration')
        parser.add_argument('-o', '--out-dir', dest='out_dir',
                            help='directory to store captured data files')
        parser.add_argument('--timeout', type=float, default=1.0,
                            help='connection timeout to get the certificate')
        parser.add_argument('-c', '--ca',
                            help='cafile or capath with custom CA to validate the certs')
        parser.add_argument('--hostname-check', action='store_true',
                            help='check hostname to be set correctly')
        # TODO:
        parser.add_argument('-d', '--days', type=int,
                            help='warn when cert expires less then in number of days (TODO)')
        parser.add_argument('-w', '--warnings', action='store_true',
                            help='only print certs with issues (TODO)')
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
        '''Run non-blocking data processing'''

        # Prepare the process
        self._process_prepare()

        # Run feed thread
        self._feed_thread = threading.Thread(target=self._process_feed)
        self._feed_thread.start()

        # Run the main workers
        for i in range(self._cfg.threads_max):
            # TODO: Remove workers if the number is lower than num of threads
            if len(self._workers) > i:
                if not self._workers[i].is_alive():
                    thread = threading.Thread(
                            target=self._worker_thread, args=(self._process_input,))
                    thread.start()
                    self._workers[i] = thread
            else:
                thread = threading.Thread(
                        target=self._worker_thread, args=(self._process_input,))
                thread.start()
                self._workers.append(thread)

        # Run results thread
        self._results_thread = threading.Thread(target=self._process_results)
        self._results_thread.start()

    def _worker_thread(self, func):
        '''Simple worker gets data from queue and feeds the processing function with it'''
        while self._enabled:
            try:
                data = self._queue_in.get(True, 0.1)
                try:
                    result = func(data)
                    self._queue_out.put(result)
                except Exception as e:
                    eprint('ERROR: Exception during processing of %s: %s' % (data, e))

            except queue.Empty:
                if not self._feed_thread.is_alive():
                    break

    def _process_prepare(self):
        '''Run the validation process as a separated thread'''
        if self._cfg.verbose:
            eprint('DEBUG: Running process prepare')
        self._queue_in = queue.Queue()
        self._queue_out = queue.Queue()
        self._enabled = True

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

        # Create reusable SSL context, because the configs are the same
        # Canary context to get the certificate and data
        self._ctx_canary = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self._ctx_canary.verify_mode = ssl.CERT_NONE
        # Real context to verify the cert
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self._ctx.verify_mode = ssl.CERT_REQUIRED
        if self._cfg.hostname_check:
            self._ctx.check_hostname = True
        if self._cfg.ca:
            if os.path.isdir(self._cfg.ca):
                self._ctx.load_verify_locations(capath=self._cfg.ca)
            elif os.path.isfile(self._cfg.ca):
                self._ctx.load_verify_locations(cafile=self._cfg.ca)
            else:
                raise Exception('ERROR: Not existing cafile/capath is specified:', self._cfg.ca)
        else:
            self._ctx.load_default_certs()

        if self._cfg.verbose:
            eprint('DEBUG: SSL Context stats:', self._ctx.cert_store_stats())
            eprint('DEBUG: SSL Context CA certs:', self._ctx.get_ca_certs())
            eprint('DEBUG: SSL default verify paths:', ssl.get_default_verify_paths())

    def _process_feed(self):
        '''Getting data from file/stdin and put to queue_in'''
        if self._cfg.verbose:
            eprint('DEBUG: Running process feed')
        # TODO: Limit data read: no more than 4x of the workers pool
        if self._cfg.file_list:
            for line in self._file_in:
                self._queue_in.put(self.prepare_address(line.rstrip()))
        if self._cfg.verbose:
            eprint('DEBUG: End process feed')

    def _process_input(self, address):
        '''Processing address'''
        result = {
            'address': address,
            'cert_pem': None,
            'cert_data': None,
            'not_after': None,
            'errors': [],
        }

        try:
            # Canary request the server certificate in PEM and ensure host is ok
            # TODO: that will be better to decode the cert and show info for the user
            # but looks like it's hard without the additional (not-builtin) modules
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = self._ctx_canary.wrap_socket(sock, server_hostname=address[0])
            ssl_sock.connect(address)
            # Getting only PEM, because data requires validation of the cert
            result['cert_pem'] = ssl.DER_cert_to_PEM_cert(ssl_sock.getpeercert(True))
            ssl_sock.close()
            eprint('DEBUG: Canary results:', result)

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
                    eprint('DEBUG: SSL error for address', address, e)
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

        return result

    def _process_results(self):
        '''Processing results data'''
        if self._cfg.verbose:
            eprint('DEBUG: Running process result')
        # Using a couple of array and dict to sort during insert
        sort_id = []
        sort_data = {}

        while self._enabled:
            try:
                res = self._queue_out.get(True, 0.1)

                if self._cfg.sort and not res['errors']:
                    # Sort only valid results
                    secs = int((res['not_after'] - datetime(1970, 1, 1)).total_seconds())
                    bisect.insort(sort_id, secs)
                    sort_data[secs] = res
                else:
                    status = 'FAILURE' if res['errors'] else ('%dd' % (
                        res['not_after'] - datetime.now()).days)
                    print('%s - %s:%d' % (status, res['address'][0], res['address'][1]))

                if res['cert_pem'] and self._cfg.out_dir:
                    # Save pem file
                    out_file = os.path.join(self._cfg.out_dir, '%s_%d.pem' % res['address'])
                    with open(out_file, 'w') as f:
                        f.write(res['cert_pem'])
            except queue.Empty:
                # Check all the workers is alive
                alive = False
                for worker in self._workers:
                    alive = worker.is_alive()
                    if alive:
                        break
                if not alive:
                    break

        # Print sorted data
        now = datetime.now()
        if self._cfg.sort:
            for i in sort_id:
                res = sort_data[i]
                diff = res['not_after'] - now
                print('%sd left - %s:%d' % (diff.days, res['address'][0], res['address'][1]))

        if self._cfg.verbose:
            eprint('DEBUG: End process result')

    def wait(self):
        '''Wait until all the list will be processed'''
        try:
            self._results_thread.join()
        except KeyboardInterrupt:
            self._enabled = False
            eprint('KeyboardInterrupt catched, stopping the program')
        except:
            self._enabled = False
            eprint('Unknown exception happened')
            raise


def main():
    '''Executing the validation process with cli arguments'''
    cv = CertValidator(sys.argv[1:])
    cv.process()
    cv.wait()

if __name__ == '__main__':
    main()
