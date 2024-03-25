import json
import os

from burp import IBurpExtender, IRequestInfo


class AllInFuzzerUtils():

    def __init__(self, helpers):
        self.helpers = helpers

    def get_components_dir(self):
        return "{}/Components".format(os.getcwd())

    def get_wordlists_dir(self):
        return "{}/Wordlists".format(os.getcwd())

    def get_settings(self):
        with open('{}/settings.json'.format(self.get_components_dir()), 'r') as f:
            settings = json.loads(f.readline())
            return settings

    def safe_bytes_to_string(self, byte_array):
        if bytes is None:
            return str()
        return self.helpers.bytesToString(byte_array)

    def update_content_length(self, request, payload):
        request_info = self.helpers.analyzeRequest(request)
        headers = request_info.getHeaders()

        for header in headers:
            split = header.split(":", 1)

            if len(split) != 2:
                continue

            header_name = split[0]

            if "content-length" != header_name.lower():
                continue

            new_header = "{}: {}".format(header_name, len(payload.decode('utf-8')))
            new_request = self.safe_bytes_to_string(request).replace(header, new_header)
            new_request_bytes = self.helpers.stringToBytes(new_request)
            return new_request_bytes

        # if content-length not found
        new_header = "{}: {}".format("content-length", len(payload.decode('utf-8')))
        headers.append(new_header)
        new_request = '\r\n'.join(headers)
        new_request += '\r\n\r\n'
        new_request += payload
        new_request_bytes = self.helpers.stringToBytes(new_request)
        return new_request_bytes
