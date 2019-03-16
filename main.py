from urllib.parse import urlsplit, parse_qs, parse_qsl, urlencode, urlunsplit
import hashlib
import os

url = 'http://someserver.com/?B02K_VERS=0003&B02K_TIMESTMP=50020181017141433899056&B02K_IDNBR=2512408990&B02K_STAMP=20010125140015123456&B02K_CUSTNAME=FIRST%20LAST&B02K_KEYVERS=0001&B02K_ALG=03&B02K_CUSTID=9984&B02K_CUSTTYPE=02&B02K_MAC=EBA959A76B87AE8996849E7C0C08D4AC44B053183BE12C0DAC2AD0C86F9F2542'


def _validateUrl(queryObj):
    queriesConcat = ""
    for key, value in queryObj.items():
        if key != "B02K_MAC":
            queriesConcat += "{}&".format(value)

    signature = hashlib.sha256(queriesConcat.encode('utf-8')).hexdigest()

    if signature == queryObj.get("B02K_MAC").lower():
        return True

    return False


def _processSignedURL(splitResult, customerName):
    nameArray = customerName.lower().split(" ")

    queryObj = {
        "firstname": nameArray[0].capitalize(),
        "lastname": nameArray[-1].capitalize()
    }

    toBeHashed = urlencode(queryObj) + "#" + os.environ["OUTPUT_SECRET"]
    queryObj["hash"] = hashlib.sha256(
        toBeHashed.encode('utf-8')).hexdigest()

    signedURL = urlunsplit((splitResult.scheme, splitResult.netloc,
                            splitResult.path, urlencode(queryObj), ""))
    return signedURL


def sign(url):
    if "INPUT_SECRET" not in os.environ:
        raise ValueError("Environment variable INPUT_SECRET not found")

    if "OUTPUT_SECRET" not in os.environ:
        raise ValueError("Environment variable OUTPUT_SECRET not found")

    splitResult = urlsplit(url)
    queryObj = dict(parse_qsl(splitResult.query))
    queryObj["input_secret"] = os.environ["INPUT_SECRET"]

    if not _validateUrl(queryObj):
        return "Invalid url"

    return _processSignedURL(splitResult, queryObj["B02K_CUSTNAME"])


print(sign(url))
