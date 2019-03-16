from urllib.parse import urlsplit, parse_qs, parse_qsl
import hashlib
import os

url = 'http://someserver.com/?B02K_VERS=0003&B02K_TIMESTMP=50020181017141433899056&B02K_IDNBR=2512408990&B02K_STAMP=20010125140015123456&B02K_CUSTNAME=FIRST%20LAST&B02K_KEYVERS=0001&B02K_ALG=03&B02K_CUSTID=9984&B02K_CUSTTYPE=02&B02K_MAC=EBA959A76B87AE8996849E7C0C08D4AC44B053183BE12C0DAC2AD0C86F9F2542'


def validateSignature(url):
    if "INPUT_SECRET" not in os.environ:
        raise ValueError("Environment variable INPUT_SECRET not found")

    splitResult = urlsplit(url)
    paramObj = dict(parse_qsl(splitResult.query))
    if paramObj.get("B02K_MAC") == None:
        raise ValueError("Request's signature is missing")

    queriesConcat = ""
    for key, value in paramObj.items():
        if key != "B02K_MAC":
            queriesConcat += "{}&".format(value)
    queriesConcat += os.environ["INPUT_SECRET"] + "&"

    calculatedSign = hashlib.sha256(queriesConcat.encode('utf-8')).hexdigest()

    return calculatedSign == paramObj.get("B02K_MAC").lower()


print(validateSignature(url))
