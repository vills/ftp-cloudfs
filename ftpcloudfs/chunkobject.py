
import logging
from urllib import quote
from httplib import HTTPException
from socket import timeout
from ssl import SSLError
from swiftclient.client import ClientException, http_connection

from ftpcloudfs.utils import smart_str

class ChunkObject(object):

    def __init__(self, conn, container, name, content_type=None):
        # FIXME
        # self._name_check()

        parsed, self.conn = http_connection(conn.url)

        logging.debug("ChunkObject: new connection open (%r, %r)" % (parsed, self.conn))

        path = '%s/%s/%s' % (parsed.path.rstrip('/'),
                             quote(smart_str(container)),
                             quote(smart_str(name)),
                             )
        headers = { 'X-Auth-Token': conn.token,
                    'Content-Type': content_type or 'application/octet-stream',
                    'Transfer-Encoding': 'chunked',
                    # User-Agent ?
                    }
        if conn.real_ip:
            headers['X-Forwarded-For'] = conn.real_ip

        # we can't use the generator interface offered by requests to do a
        # chunked transfer encoded PUT, so we do this is to get control over the
        # "real" http connection and do the HTTP request ourselves
        self.raw_conn = self.conn.request_session.get_adapter(conn.url).get_connection(conn.url)._get_conn()

        self.raw_conn.putrequest('PUT', path)
        for key, value in headers.iteritems():
            self.raw_conn.putheader(key, value)
        self.raw_conn.endheaders()
        logging.debug("ChunkedObject: path=%r, headers=%r" % (path, headers))

    def send_chunk(self, chunk):
        logging.debug("ChunkObject: sending %s bytes" % len(chunk))
        try:
            self.raw_conn.send("%X\r\n" % len(chunk))
            self.raw_conn.send(chunk)
            self.raw_conn.send("\r\n")
        except (timeout, SSLError, HTTPException), err:
            raise ClientException(err.message)

    def finish_chunk(self):
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

        if response.status // 100 != 2:
            raise ClientException(response.reason,
                                  http_status=response.status,
                                  http_reason=response.reason,
                                  )

