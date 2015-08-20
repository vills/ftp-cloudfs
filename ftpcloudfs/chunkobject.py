
import logging
from urllib import quote
from httplib import HTTPException
from socket import timeout
from ssl import SSLError
from swiftclient.client import ClientException, http_connection

from ftpcloudfs.utils import smart_str

class ChunkObject(object):

    def __init__(self, conn, container, name, content_type=None, reuse_token = True):
        self.raw_conn = None

        if reuse_token:
            self.url = conn.url
            token = conn.token
        else:
            self.url, token = conn.get_auth()
        self.parsed, self.conn = http_connection(self.url)

        self.path = '%s/%s/%s' % (self.parsed.path.rstrip('/'),
                                  quote(smart_str(container)),
                                  quote(smart_str(name)),
                                  )
        self.headers = { 'X-Auth-Token': token,
                         'Content-Type': content_type or 'application/octet-stream',
                         'Transfer-Encoding': 'chunked',
                         'Connection': 'close',
                         # User-Agent ?
                         }
        if conn.real_ip:
            self.headers['X-Forwarded-For'] = conn.real_ip

        logging.debug("ChunkedObject: path=%r, headers=%r" % (self.path, self.headers))

        self.already_sent = 0

    def _open_connection(self):
        logging.debug("ChunkObject: new connection open (%r, %r)" % (self.parsed, self.conn))

        # we can't use the generator interface offered by requests to do a
        # chunked transfer encoded PUT, so we do this is to get control over the
        # "real" http connection and do the HTTP request ourselves
        self.raw_conn = self.conn.request_session.get_adapter(self.url).get_connection(self.url)._get_conn()

        self.raw_conn.putrequest('PUT', self.path, skip_accept_encoding=True)
        for key, value in self.headers.iteritems():
            self.raw_conn.putheader(key, value)
        self.raw_conn.endheaders()

    def send_chunk(self, chunk):
        if self.raw_conn is None:
            self._open_connection()

        logging.debug("ChunkObject: sending %s bytes" % len(chunk))
        try:
            self.raw_conn.send("%X\r\n" % len(chunk))
            self.raw_conn.send(chunk)
            self.raw_conn.send("\r\n")
        except (timeout, SSLError, HTTPException), err:
            raise ClientException(err.message)
        else:
            self.already_sent += len(chunk)
            logging.debug("ChunkObject: already sent %s bytes" % self.already_sent)

    def finish_chunk(self):
        if self.raw_conn is None:
            self._open_connection()

        logging.debug("ChunkObject: finish_chunk")
        try:
            self.raw_conn.send("0\r\n\r\n")
            response = self.raw_conn.getresponse()
        except (timeout, SSLError, HTTPException), err:
            self.raw_conn.close()
            raise ClientException(err.message)

        try:
            response.read()
        except (timeout, SSLError):
            # this is not relevant, keep going
            pass

        # we always close the connection
        self.raw_conn.close()
        self.conn.request_session.close()

        if response.status // 100 != 2:
            raise ClientException(response.reason,
                                  http_status=response.status,
                                  http_reason=response.reason,
                                  )

