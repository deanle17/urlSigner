from urllib.parse import urlsplit, parse_qs, parse_qsl, urlencode, urlunsplit
import hashlib
import os

INPUT_SECRET = "INPUT_SECRET"
OUTPUT_SECRET = "OUTPUT_SECRET"
B02K_MAC = "B02K_MAC"


def _validate_signature(queryObj):
    queriesConcat = ""
    for key, value in queryObj.items():
        if key != B02K_MAC:
            queriesConcat += "{}&".format(value)

    signature = hashlib.sha256(queriesConcat.encode('utf-8')).hexdigest()

    return signature == queryObj.get(B02K_MAC).lower()


def _process_signed_url(splittedURL, customerName, outputSecret):
    nameArray = customerName.lower().split(" ")

    if len(nameArray) < 2:
        return "Not enough customer's name information"

    newQueryObj = {
        "firstname": nameArray[0].capitalize(),
        "lastname": nameArray[-1].capitalize()
    }

    toBeHashed = urlencode(newQueryObj) + "#" + outputSecret
    newQueryObj["hash"] = hashlib.sha256(
        toBeHashed.encode('utf-8')).hexdigest()

    signedURL = urlunsplit((splittedURL.scheme, splittedURL.netloc,
                            splittedURL.path, urlencode(newQueryObj), ""))

    return signedURL


def sign(url, encoding="cp1252"):
    if INPUT_SECRET not in os.environ:
        return "Environment variable INPUT_SECRET not found"

    if OUTPUT_SECRET not in os.environ:
        return "Environment variable OUTPUT_SECRET not found"

    splittedURL = urlsplit(url)
    queryObj = dict(parse_qsl(splittedURL.query, encoding=encoding))

    if B02K_MAC not in queryObj:
        return "Signature is missing"

    queryObj["input_secret"] = os.environ[INPUT_SECRET]

    if not _validate_signature(queryObj):
        return "Invalid URL"

    return _process_signed_url(splittedURL, queryObj["B02K_CUSTNAME"], os.environ[OUTPUT_SECRET])
