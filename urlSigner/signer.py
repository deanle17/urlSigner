from urllib.parse import urlsplit, parse_qs, parse_qsl, urlencode, urlunsplit
import hashlib
import os


def _validateSignature(queryObj):
    queriesConcat = ""
    for key, value in queryObj.items():
        if key != "B02K_MAC":
            queriesConcat += "{}&".format(value)

    signature = hashlib.sha256(queriesConcat.encode('utf-8')).hexdigest()

    if signature == queryObj.get("B02K_MAC").lower():
        return True

    return False


def _processSignedURL(splittedURL, customerName, outputSecret):
    nameArray = customerName.lower().split(" ")

    queryObj = {
        "firstname": nameArray[0].capitalize(),
        "lastname": nameArray[-1].capitalize()
    }

    toBeHashed = urlencode(queryObj) + "#" + outputSecret
    queryObj["hash"] = hashlib.sha256(
        toBeHashed.encode('utf-8')).hexdigest()

    signedURL = urlunsplit((splittedURL.scheme, splittedURL.netloc,
                            splittedURL.path, urlencode(queryObj), ""))

    return signedURL


def sign(url):
    if "INPUT_SECRET" not in os.environ:
        return "Environment variable INPUT_SECRET not found"

    if "OUTPUT_SECRET" not in os.environ:
        return "Environment variable OUTPUT_SECRET not found"

    splittedURL = urlsplit(url)
    queryObj = dict(parse_qsl(splittedURL.query))
    queryObj["input_secret"] = os.environ["INPUT_SECRET"]

    if not _validateSignature(queryObj):
        return "Invalid URL"

    return _processSignedURL(splittedURL, queryObj["B02K_CUSTNAME"], os.environ["OUTPUT_SECRET"])
