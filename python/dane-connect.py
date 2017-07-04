#!/usr/bin/env python

from getdns import *
from M2Crypto import SSL, X509
import sys
from socket import *
import hashlib

if len(sys.argv) > 1:
        hostname = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
else:
        print('%s <hostname> [ <port> ]' % sys.argv[0])
        sys.exit(0)

ctx = Context()
ctx.resolution_type = RESOLUTION_STUB
ext = { "dnssec_return_only_secure" : EXTENSION_TRUE }

      #, "dnssec_roadblock_avoidance": EXTENSION_TRUE }

# Correctly query and process DANE records
res = ctx.general('_%d._tcp.%s' % (port, hostname), RRTYPE_TLSA, ext)
if res.status == RESPSTATUS_GOOD:
    # Process TLSA Rrs
    tlsas = [ answer for reply in res.replies_tree
                     for answer in reply['answer']
                      if answer['type'] == RRTYPE_TLSA ]

elif res.status == RESPSTATUS_ALL_TIMEOUT:
    print('Network error trying to get DANE records for %s' % hostname)
    sys.exit(-1);
elif res.status == RESPSTATUS_ALL_BOGUS_ANSWERS:
    print('DANE records for %s were BOGUS' % hostname)
    sys.exit(-1);
else:
    tlsas = None
    # Conventional PKIX without DANE processing

ca_cert = None
def get_ca(ok, store):
    global ca_cert
    if store.get_current_cert().check_ca():
        ca_cert = store.get_current_cert()
    return ok

# Now TLS connect to each address  and verify the cert (or CA)
for address in ctx.address(hostname).just_address_answers:
    sock = socket(AF_INET if address['address_type'] == 'IPv4'
             else AF_INET6, SOCK_STREAM)
    socket.setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1)
    print('Connecting to %s' % address['address_data']);
    ssl_ctx = SSL.Context()
    ssl_ctx.load_verify_locations(capath = '/etc/ssl/certs')
    ssl_ctx.set_verify(SSL.verify_none, 10, get_ca)
    connection = SSL.Connection(ssl_ctx, sock=sock)

    # set TLS SNI extension
    connection.set_tlsext_host_name(hostname)

    # Per RFC7671, for DANE-EE usage, certificate identity checks are
    # based solely on the TLSA record, so we ignore name mismatch 
    # conditions in the certificate.
    try:
        connection.connect((address['address_data'], port))

    except SSL.Checker.WrongHost:
        pass
    except error:
        continue

    if not tlsas:
        print( 'No TLSAS. Regular PKIX validation '
             + ('succeeded' if connection.verify_ok() else 'failed'))
        continue # next address

    cert = connection.get_peer_cert()
    TLSA_matched = False
    for tlsa in tlsas:
        rdata = tlsa['rdata']
        if rdata['certificate_usage'] in (0, 2):
            cert = ca_cert

        if rdata['selector'] == 0:
            certdata = cert.as_der()
        elif rdata['selector'] == 1:
            certdata = cert.get_pubkey().as_der()
        else:
            raise ValueError('Unkown selector')

        if rdata['matching_type'] == 1:
            certdata = hashlib.sha256(certdata).digest()
        elif rdata['matching_type'] == 2:
            certdata = hashlib.sha512(certdata).digest()
        else:
            raise ValueError('Unkown matching type')
        if str(certdata) == str(rdata['certificate_association_data'])\
        and (rdata['certificate_usage'] > 1 or connection.verify_ok()):
            TLSA_matched = True
            print('DANE validated successfully')
            break # from "for tlsa in tlsas:" (first one wins!)

    if not TLSA_matched:
        print('DANE validation failed')


