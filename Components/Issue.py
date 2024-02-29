from base64 import b64decode, b64encode


class Issue():
    """Issue represents one finding."""
    index = None  # type: int
    host = ""  # type: str
    component = ""  # type: str
    payload = ""  # type: str
    status_code = 0  # type: int
    header_count = 0  # type: int
    response_length = 0  # type: int
    body_offset = 0  # type: int
    # request and response will be stored as base64 encoded strings.
    request = ""  # type: str
    response = ""  # type: str

    def getRequest(self):
        # type: () -> bytearray
        """Base64 decode the request and return the results."""
        return b64decode(self.request)

    def setRequest(self, req):
        # type: (bytearray) -> None
        """Base64 encode the request and store it."""
        self.request = b64encode(req)

    def getResponse(self):
        # type: () -> bytearray
        """Base64 decode the response and return the results."""
        return b64decode(self.response)

    def setResponse(self, resp):
        # type: (bytearray) -> None
        """Base64 encode the response and store it."""
        self.response = b64encode(resp)

    def __init__(self, request, response, host="", component="", payload="", status_code=0, response_length=0, body_offset = 0, header_count=0):
        """Create the issue."""
        self.host = host
        self.component = component
        self.payload = payload
        self.status_code = status_code
        self.response_length = response_length
        self.body_offset = body_offset
        self.header_count = header_count
        self.setRequest(request)
        self.setResponse(response)
