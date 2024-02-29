import urlparse
import json
import copy
from Cookie import SimpleCookie


class PayloadGenerator():

    def __init__(self, wordlist_dir):
        self.wordlist_dir = wordlist_dir

    def params_payloads(self, params):
        payloads = []

        file = open("{}/AppendList.txt".format(self.wordlist_dir), "r")
        fuzz = [line.strip() for line in file.readlines()]
        fuzz.append('\x00')

        # insert at the end of the parameter
        for param in params:
            for f in fuzz:
                new_params = copy.deepcopy(params)
                new_params[param] += f
                new_query = '&'.join(["{}={}".format(key, ''.join(value)) for key, value in new_params.items()])
                new_query = new_query.replace(' ', "%09")
                payloads.append(new_query)

        # insert at the start of the parameter
        for param in params:
            for f in fuzz:
                new_params = copy.deepcopy(params)
                new_params[param] = [f + ''.join(new_params[param])]
                new_query = '&'.join(["{}={}".format(key, ''.join(value)) for key, value in new_params.items()])
                new_query = new_query.replace(' ', "%09")
                payloads.append(new_query)

        return payloads

    def params_payloads_from_url(self, url):
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qs(parsed.query)
        return self.params_payloads(params)

    def params_payloads_from_query(self, query):
        params = urlparse.parse_qs(query)
        return self.params_payloads(params)

    def headers_payloads(self, headers, skip_headers=list):
        # type: (list) -> [(str, str)]

        payloads = []
        file = open("{}/AppendList.txt".format(self.wordlist_dir), "r")
        fuzz = [line.strip() for line in file.readlines()]
        fuzz.append('\x00')

        for header in headers:
            split = header.split(":", 1)
            if len(split) != 2:
                continue

            header_name = split[0]
            header_value = split[1]

            for skip in skip_headers:
                if split[0].lower() == skip.lower():
                    continue

            # insert at the end of the header
            for f in fuzz:
                new_header_value = header_value.lstrip() + f
                new_header_string = "{}: {}".format(header_name, new_header_value)
                payloads.append((header, new_header_string))

            # insert at the start of the header
            for f in fuzz:
                new_header_value = f + header_value.lstrip()
                new_header_string = "{}: {}".format(header_name, new_header_value)
                payloads.append((header, new_header_string))

        return payloads

    def json_payload(self, json_string):
        payloads = []
        try:
            data = json.loads(json_string)
        except:
            print "Wrong json format"
            return []

        def process_value(val):
            if isinstance(val, dict):
                for key, value in val.items():
                    if isinstance(value, list):
                        for idx, item in enumerate(value):
                            if isinstance(item, (dict, list)):
                                process_value(item)
                            else:
                                original_item = value[idx]
                                value[idx] = "FUZZ"
                                payloads.append(json.dumps(data))
                                value[idx] = original_item
                    else:
                        original_val = val[key]
                        val[key] = "FUZZ"
                        payloads.append(json.dumps(data))
                        val[key] = original_val
            elif isinstance(val, list):
                for idx, item in enumerate(val):
                    if isinstance(item, (dict, list)):
                        process_value(item)
                    else:
                        original_item = val[idx]
                        val[idx] = "FUZZ"
                        payloads.append(json.dumps(data))
                        val[idx] = original_item

        process_value(data)
        return payloads

    def json_payloads(self, json_string):
        payloads = []
        payloads_fuzz = self.json_payload(json_string)
        file = open("{}/JsonList.txt".format(self.wordlist_dir), "r")

        fuzz = [line.strip() for line in file.readlines()]

        for f in fuzz:
            [payloads.append(p.replace('"FUZZ"', f)) for p in payloads_fuzz]

        return payloads

    def cookies_payloads(self, headers):
        def encode_cookie(cookies):
            result = ""
            for cookie_param_name in cookies:
                result += "{}={}; ".format(cookie_param_name, cookies[cookie_param_name])
            return result

        payloads = []
        cookie_header = ""
        cookie_value = ""
        cookie_original = ""
        file = open("{}/AppendList.txt".format(self.wordlist_dir), "r")
        fuzz = [line.strip() for line in file.readlines()]

        for header in headers:
            split = header.split(":", 1)
            if len(split) != 2:
                continue
            if split[0].lower() == "cookie":
                cookie_header = split[0].encode()
                cookie_value = split[1].encode()
                cookie_original = header
                break

        cookies_simple = SimpleCookie()
        cookies_simple.load(cookie_value)
        cookies_dict = {k: v.value for k, v in cookies_simple.items()}

        for cookie_param_name in cookies_dict:
            for f in fuzz:
                cookie_param_value = cookies_dict[cookie_param_name]
                cookies_dict[cookie_param_name] = cookie_param_value + f
                payloads.append((cookie_original, "{}: {}".format(cookie_header, encode_cookie(cookies_dict))))
                cookies_dict[cookie_param_name] = cookie_param_value

        for cookie_param_name in cookies_dict:
            for f in fuzz:
                cookie_param_value = cookies_dict[cookie_param_name]
                cookies_dict[cookie_param_name] = f + cookie_param_value
                payloads.append((cookie_original, "{}: {}".format(cookie_header, encode_cookie(cookies_dict))))
                cookies_dict[cookie_param_name] = cookie_param_value

        # Experimental. RFC 2109,2965
        cookies_dict["$Version"] = '"0"'
        payloads.append((cookie_original, "{}: {}".format(cookie_header, encode_cookie(cookies_dict))))
        cookies_dict["$Version"] = "0"
        payloads.append((cookie_original, "{}: {}".format(cookie_header, encode_cookie(cookies_dict))))
        cookies_dict["$Version"] = '"1"'
        payloads.append((cookie_original, "{}: {}".format(cookie_header, encode_cookie(cookies_dict))))
        cookies_dict["$Version"] = "1"
        payloads.append((cookie_original, "{}: {}".format(cookie_header, encode_cookie(cookies_dict))))

        return payloads
