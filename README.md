# URL Signer

## Installation

Install package by using

```shell
pip3 install urlSigner
```

## Usage

1.  Set environment variable **INPUT_SECRET** and **OUTPUT_SECRET**
2.  Import package:

```python
from urlSigner import signer
```

3. Call _sign_ function:

```python
signedURL = signer.sign("https://www.google.com")
print(signedURL)
```
