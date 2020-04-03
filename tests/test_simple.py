'''
Unit test for  import and run against well-known hosts
'''

from .. CertValidator import CertValidator


class TestSimple:
    def test_default(self):
        cv = CertValidator([
            '-n', 'www.google.com,www.apple.com',
            '-o', 'pems_1',
            '-s', '-v',
        ])
        cv.process()
        cv.wait()
