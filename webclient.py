from time import time
from urlparse import urlparse, urlunparse, urldefrag

from twisted.python import failure
from twisted.web.client import HTTPClientFactory
from twisted.web.http import HTTPClient
from twisted.internet import defer

from scrapy.http import Headers
from scrapy.utils.httpobj import urlparse_cached
from scrapy.responsetypes import responsetypes
from scrapy import optional_features
from scrapy import log
from copy import deepcopy

def _parsed_url_args(parsed):
    path = urlunparse(('', '', parsed.path or '/', parsed.params, parsed.query, ''))
    host = parsed.hostname
    port = parsed.port
    scheme = parsed.scheme
    netloc = parsed.netloc
    if port is None:
        port = 443 if scheme == 'https' else 80
    return scheme, netloc, host, port, path


def _parse(url):
    url = url.strip()
    parsed = urlparse(url)
    return _parsed_url_args(parsed)

class _IdentityTransferDecoder(object):
    """
    Protocol for accumulating bytes up to a specified length.  This handles the
    case where no I{Transfer-Encoding} is specified.

    @ivar contentLength: Counter keeping track of how many more bytes there are
        to receive.

    @ivar dataCallback: A one-argument callable which will be invoked each
        time application data is received.

    @ivar finishCallback: A one-argument callable which will be invoked when
        the terminal chunk is received.  It will be invoked with all bytes
        which were delivered to this protocol which came after the terminal
        chunk.
    """
    def __init__(self, contentLength, dataCallback, finishCallback):
        self.contentLength = contentLength
        self.dataCallback = dataCallback
        self.finishCallback = finishCallback


    def dataReceived(self, data):
        """
        Interpret the next chunk of bytes received.  Either deliver them to the
        data callback or invoke the finish callback if enough bytes have been
        received.

        @raise RuntimeError: If the finish callback has already been invoked
            during a previous call to this methood.
        """
        if self.dataCallback is None:
            raise RuntimeError(
                "_IdentityTransferDecoder cannot decode data after finishing")

        if self.contentLength is None:
            self.dataCallback(data)
        elif len(data) < self.contentLength:
            self.contentLength -= len(data)
            self.dataCallback(data)
        else:
            # Make the state consistent before invoking any code belonging to
            # anyone else in case noMoreData ends up being called beneath this
            # stack frame.
            contentLength = self.contentLength
            dataCallback = self.dataCallback
            finishCallback = self.finishCallback
            self.dataCallback = self.finishCallback = None
            self.contentLength = 0

            dataCallback(data[:contentLength])
            finishCallback(data[contentLength:])


    def noMoreData(self):
        """
        All data which will be delivered to this decoder has been.  Check to
        make sure as much data as was expected has been received.

        @raise PotentialDataLoss: If the content length is unknown.
        @raise _DataLoss: If the content length is known and fewer than that
            many bytes have been delivered.

        @return: C{None}
        """
        finishCallback = self.finishCallback
        self.dataCallback = self.finishCallback = None
        if self.contentLength is None:
            finishCallback('')
            raise PotentialDataLoss()
        elif self.contentLength != 0:
            raise _DataLoss()


class _ChunkedTransferDecoder(object):
    """
    Protocol for decoding I{chunked} Transfer-Encoding, as defined by RFC 2616,
    section 3.6.1.  This protocol can interpret the contents of a request or
    response body which uses the I{chunked} Transfer-Encoding.  It cannot
    interpret any of the rest of the HTTP protocol.

    It may make sense for _ChunkedTransferDecoder to be an actual IProtocol
    implementation.  Currently, the only user of this class will only ever
    call dataReceived on it.  However, it might be an improvement if the
    user could connect this to a transport and deliver connection lost
    notification.  This way, `dataCallback` becomes `self.transport.write`
    and perhaps `finishCallback` becomes `self.transport.loseConnection()`
    (although I'm not sure where the extra data goes in that case).  This
    could also allow this object to indicate to the receiver of data that
    the stream was not completely received, an error case which should be
    noticed. -exarkun

    @ivar dataCallback: A one-argument callable which will be invoked each
        time application data is received.

    @ivar finishCallback: A one-argument callable which will be invoked when
        the terminal chunk is received.  It will be invoked with all bytes
        which were delivered to this protocol which came after the terminal
        chunk.

    @ivar length: Counter keeping track of how many more bytes in a chunk there
        are to receive.

    @ivar state: One of C{'chunk-length'}, C{'trailer'}, C{'body'}, or
        C{'finished'}.  For C{'chunk-length'}, data for the chunk length line
        is currently being read.  For C{'trailer'}, the CR LF pair which
        follows each chunk is being read.  For C{'body'}, the contents of a
        chunk are being read.  For C{'finished'}, the last chunk has been
        completely read and no more input is valid.

    @ivar finish: A flag indicating that the last chunk has been started.  When
        it finishes, the state will change to C{'finished'} and no more data
        will be accepted.
    """
    state = 'chunk-length'
    finish = False

    def __init__(self, dataCallback, finishCallback):
        self.dataCallback = dataCallback
        self.finishCallback = finishCallback
        self._buffer = ''


    def dataReceived(self, data):
        """
        Interpret data from a request or response body which uses the
        I{chunked} Transfer-Encoding.
        """
        data = self._buffer + data
        self._buffer = ''
        while data:
            if self.state == 'chunk-length':
                if '\r\n' in data:
                    line, rest = data.split('\r\n', 1)
                    parts = line.split(';')
                    self.length = int(parts[0], 16)
                    if self.length == 0:
                        self.state = 'trailer'
                        self.finish = True
                    else:
                        self.state = 'body'
                    data = rest
                else:
                    self._buffer = data
                    data = ''
            elif self.state == 'trailer':
                if data.startswith('\r\n'):
                    data = data[2:]
                    if self.finish:
                        self.state = 'finished'
                        self.finishCallback(data)
                        data = ''
                    else:
                        self.state = 'chunk-length'
                else:
                    self._buffer = data
                    data = ''
            elif self.state == 'body':
                if len(data) >= self.length:
                    chunk, data = data[:self.length], data[self.length:]
                    self.dataCallback(chunk)
                    self.state = 'trailer'
                elif len(data) < self.length:
                    self.length -= len(data)
                    self.dataCallback(data)
                    data = ''
            elif self.state == 'finished':
                raise RuntimeError(
                    "_ChunkedTransferDecoder.dataReceived called after last "
                    "chunk was processed")

    def noMoreData(self):
        """
        Verify that all data has been received.  If it has not been, raise
        L{_DataLoss}.
        """
        if self.state != 'finished':
            raise _DataLoss(
                "Chunked decoder in %r state, still expecting more data to "
                "get to finished state." % (self.state,))


class myHTTPClient(HTTPClient):

    def sendCommand(self, command, path):
        self.transport.write('%s %s HTTP/1.1\r\n' % (command, path))


    def extractHeader(self, header):
        """
        Given a complete HTTP header, extract the field name and value and
        process the header.

        @param header: a complete HTTP request header of the form
            'field-name: value'.
        @type header: C{str}
        """
        key, val = header.split(':', 1)
        val = val.lstrip()
        self.handleHeader(key, val)
        if key.lower() == 'content-length':
            self.length = int(val)
            log.msg("extractHeader  UnChunk.")
            self._transferDecoder = _IdentityTransferDecoder(
                self.length, self.handleContentChunk, self._finishRequestBody)
        elif key.lower() == 'transfer-encoding' and val.lower() == 'chunked':
            self.length = None
            log.msg("extractHeader  Chunk.")
            self._transferDecoder = _ChunkedTransferDecoder(
                self.handleContentChunk, self._finishRequestBody)

    def lineReceived(self, line):
        if self.firstLine:
            self.firstLine = False
            l = line.split(None, 2)
            version = l[0]
            status = l[1]
            try:
                message = l[2]
            except IndexError:
                # sometimes there is no message
                message = ""
            self.handleStatus(version, status, message)
            return
        if not line:
            # reach the end of head
            if self._header != "":
                self.extractHeader(self._header)
            self._header = ""
            self.handleEndHeaders()
            self.__buffer = ""
            # self.__buffer = StringIO()
            if self.length == 0:
                #Something special
                self.allContentReceived()
            else:
                # use the raw-receiver
                self.setRawMode()
            return
        # Still read header lines
        if line.startswith('\t') or line.startswith(' '):
            self._header = self._header + line
        elif self._header:
            self.extractHeader(self._header)
            self._header = line
        else: # First header
            self._header = line

    def allContentReceived(self):
        self.length = 0
        self._first_line = 1
        self._transferDecoder = None

    def connectionLost(self, reason):
        log.msg("connectionLost")
        self.handleResponseEnd()

    def handleResponseEnd(self):
        """
        The response has been completely received.

        This callback may be invoked more than once per request.
        """
        if self.__buffer is not None:
            b = deepcopy(self.__buffer)
            #.getvalue()
            self.__buffer = None
            log.msg("Response length %d" % len(b))
            self.handleResponse(b)

    def rawDataReceived(self, data):
        self._transferDecoder.dataReceived(data)

    def handleContentChunk(self, data):
        log.msg("handleContentChunk. %d" % len(data))
        self.__buffer = self.__buffer + data
        self.transport.write("HTTP/1.1 100 Continue\r\n\r\n")

    def _finishRequestBody(self, data):
        log.msg("_finishRequestBody. %d" % len(data))

        self.allContentReceived()
        self.__buffer = self.__buffer + data
        self.handleResponseEnd()



class ScrapyHTTPPageGetter(myHTTPClient):

    delimiter = '\n'

    def connectionMade(self):
        self.headers = Headers() # bucket for response headers

        # Method command
        self.sendCommand(self.factory.method, self.factory.path)
        # Headers
        for key, values in self.factory.headers.items():
            for value in values:
                self.sendHeader(key, value)
        self.endHeaders()
        # Body
        if self.factory.body is not None:
            self.transport.write(self.factory.body)

    def lineReceived(self, line):
        return myHTTPClient.lineReceived(self, line.rstrip())

    def handleHeader(self, key, value):
        self.headers.appendlist(key, value)

    def handleStatus(self, version, status, message):
        self.factory.gotStatus(version, status, message)

    def handleEndHeaders(self):
        self.factory.gotHeaders(self.headers)

    def connectionLost(self, reason):
        myHTTPClient.connectionLost(self, reason)
        self.factory.noPage(reason)

    def handleResponse(self, response):
        if self.factory.method.upper() == 'HEAD':
            self.factory.page('')
        else:
            self.factory.page(response)
        self.transport.loseConnection()

    def timeout(self):
        self.transport.loseConnection()
        self.factory.noPage(\
                defer.TimeoutError("Getting %s took longer than %s seconds." % \
                (self.factory.url, self.factory.timeout)))


class ScrapyHTTPClientFactory(HTTPClientFactory):
    """Scrapy implementation of the HTTPClientFactory overwriting the
    serUrl method to make use of our Url object that cache the parse
    result.
    """

    protocol = ScrapyHTTPPageGetter
    waiting = 1
    noisy = False
    followRedirect = False
    afterFoundGet = False

    def __init__(self, request, timeout=180):
        self.url = urldefrag(request.url)[0]
        self.method = request.method
        self.body = request.body or None
        self.headers = Headers(request.headers)
        self.response_headers = None
        self.timeout = request.meta.get('download_timeout') or timeout
        self.start_time = time()
        self.deferred = defer.Deferred().addCallback(self._build_response, request)

        # Fixes Twisted 11.1.0+ support as HTTPClientFactory is expected
        # to have _disconnectedDeferred. See Twisted r32329.
        # As Scrapy implements it's own logic to handle redirects is not
        # needed to add the callback _waitForDisconnect.
        # Specifically this avoids the AttributeError exception when
        # clientConnectionFailed method is called.
        self._disconnectedDeferred = defer.Deferred()

        self._set_connection_attributes(request)

        # set Host header based on url
        self.headers.setdefault('Host', self.netloc)

        # set Content-Length based len of body
        if self.body is not None:
            self.headers['Content-Length'] = len(self.body)
            # just in case a broken http/1.1 decides to keep connection alive
            self.headers.setdefault("Connection", "close")

    def _build_response(self, body, request):
        request.meta['download_latency'] = self.headers_time-self.start_time
        status = int(self.status)
        headers = Headers(self.response_headers)
        respcls = responsetypes.from_args(headers=headers, url=self.url)
        return respcls(url=self.url, status=status, headers=headers, body=body)

    def _set_connection_attributes(self, request):
        parsed = urlparse_cached(request)
        self.scheme, self.netloc, self.host, self.port, self.path = _parsed_url_args(parsed)
        proxy = request.meta.get('proxy')
        if proxy:
            self.scheme, _, self.host, self.port, _ = _parse(proxy)
            self.path = self.url

    def gotHeaders(self, headers):
        self.headers_time = time()
        self.response_headers = headers



if 'ssl' in optional_features:
    from twisted.internet.ssl import ClientContextFactory
    from OpenSSL import SSL
else:
    ClientContextFactory = object


class ScrapyClientContextFactory(ClientContextFactory):
    "A SSL context factory which is more permissive against SSL bugs."
    # see https://github.com/scrapy/scrapy/issues/82
    # and https://github.com/scrapy/scrapy/issues/26

    def getContext(self):
        ctx = ClientContextFactory.getContext(self)
        # Enable all workarounds to SSL bugs as documented by
        # http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
        ctx.set_options(SSL.OP_ALL)
        return ctx
