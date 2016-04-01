import hashlib, hmac, base64
import requests, json

from datetime import datetime
import pytz

class Beme:
    def __init__(self):
        self.secret = "NG5MwYaHUk698gZNruU8kXPOTSHVNYkzCcCrNwC23Mc="
        self.key = "MiW46EHG8h8B8zeCA3SYBpzSCcKTML/ahIHg5lhhFIQ"

        self.valetSecret = None
        self.valetKey = None

        self.is_debug = True

        self.clientBuild = "20160322"
        self.version = "0.9"
        self.webUA = "Mozilla/5.0 (iPod touch; CPU iPhone OS 9_0_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13A452"
        self.bemeUA = "beme/{0} (iPod touch; iOS 9.0.2; Scale/2.00)".format(self.version)

        self.s = requests.Session()
        self.apiURL = "https://beta.be-me.co"

    def exchangeValet(self):
        res = self.api("GET", "/auth/valet/exchange")
        rJSON = self.getJSON(res)
        if type(rJSON) is dict:
            if "response" in rJSON:
                auth = rJSON["response"]["auth"]
                self.valetSecret = auth["secret"]
                self.valetKey = auth["auth_key"]

    def checkUsername(self, username):
        res = self.api("POST", "/users/validate/name", {"display_name": username}, valet = True)
        rJSON = self.getJSON(res)
        if type(rJSON) is dict:
            print json.dumps(rJSON, indent = 4)

    def api(self, method, endpoint, data = None, params = None, valet = False):
        method = method.upper()

        userAgent = self.webUA if valet else self.bemeUA
        authentication = self.generateAuthHeader(method, endpoint, data, valet)

        headers = {
            "Host": "beta.be-me.co",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en",
            "Connection": "keep-alive",
            "User-Agent": userAgent,
            "Authorization": authentication["authHeader"]
        }

        if authentication["md5"] != "":
            headers["content-md5" if valet else "Content-MD5"] = authentication["md5"]

        if data is not None and data != "":
            data = json.dumps(data, separators = (",", ":"))
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = len(data)

        if valet:
            headers["x-beme-date"] = authentication["date"].strftime("%a, %d %b %Y %H:%M:%S %Z")
            headers["Accept"] = "application/json"
            headers["Origin"] = "https://web.beme.com"
            if endpoint == "/users/validate/name":
                headers["Referer"] = "https://web.beme.com/onboarding/signup"
        else:
            headers["Date"] = authentication["date"].strftime("%a, %d %b %Y %H:%M:%S %z")
            headers["X-Beme-Client-Build"] = self.clientBuild
            headers["Accept"] = "*/*"

        try:
            if method == "GET":
                res = self.s.get("{0}{1}".format(self.apiURL, endpoint), data = data, params = params, headers = headers)
            elif method == "POST":
                res = self.s.post("{0}{1}".format(self.apiURL, endpoint), data = data, params = params, headers = headers)
            else:
                self.debug("Bad method type, {0}".format(method))
                return
        except requests.RequestException:
            res = type("APIError", (object,), {"status_code": None, "content": None})

        return res

    def debug(self, message):
        if self.is_debug:
            print "[DEBUG] {0}".format(message)

    @staticmethod
    def getJSON(response):
        rJSON = False
        if isinstance(response, requests.models.Response):
            try:
                rJSON = response.json()
            except ValueError:
                pass

        return rJSON

    def generateAuthHeader(self, method, path, data = None, valet = False):
        date = datetime.now(pytz.timezone("GMT"))

        if data is not None and len(data) != 0:
            m = hashlib.md5()
            m.update(json.dumps(data, separators = (",", ":")))
            md5 = m.hexdigest()
        else:
            md5 = ""

        if valet:
            dateStr = date.strftime("%a, %d %b %Y %H:%M:%S %Z")

            parts = [
                method.upper(),
                md5,
                "application/json",
                dateStr,
                "x-beme-date:{0}".format(dateStr),
                path
            ]

            authHeader = "BemeValet {0}:{1}".format(
                self.valetKey,
                base64.b64encode(
                    hmac.new(
                        key = base64.b64decode(self.valetSecret),
                        msg = "\n".join(parts),
                        digestmod = hashlib.sha1
                    ).digest()
                )
            )
        else:
            authString = "{method}\n\n\n{date}\nx-beme-client-build:{clientBuild}\n{path}".format(
                method = method.upper(),
                date = date.strftime("%a, %d %b %Y %H:%M:%S %z"),
                clientBuild = self.clientBuild,
                path = path
            )

            authHeader = "Beme {0}:{1}".format(
                self.key,
                base64.b64encode(
                    hmac.new(
                        key = base64.b64decode(self.secret),
                        msg = authString,
                        digestmod = hashlib.sha1
                    ).digest()
                )
            )

        return {
            "date": date,
            "md5": md5,
            "authHeader": authHeader
        }