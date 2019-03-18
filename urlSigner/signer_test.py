import unittest
import signer
from urllib.parse import SplitResult
from unittest.mock import patch
import os

urlBase = "https://fsecure.com/?"


class IntegrationTest(unittest.TestCase):
    def test_integration_sign_url(self):
        os.environ[signer.INPUT_SECRET] = "inputsecret"
        os.environ[signer.OUTPUT_SECRET] = "outputsecret"

        result = signer.sign(urlBase + "B02K_CUSTNAME=V%C4IN%D6%20M%C4KI&B02K_MAC=ebfa16b7dbbf887fd579099d5bbac83488fb34f6c824cc0f8d9d6e2f4d286d41")

        expected = urlBase + "firstname=V%C3%A4in%C3%B6&lastname=M%C3%A4ki&hash=6e6f22ec29ed8ec1f0be289a94dde36632720596499993b2cdfc1422b834934a"
        self.assertEqual(result, expected)


class TestValidateURL(unittest.TestCase):
    def test_validation_succeed(self):
        """Should return true if url is valid"""
        queryObj = {
            "name": "dean",
            "age": "27",
            "intput_secret": "test_secret",
            "B02K_MAC": "3d44edcfed6d58e99ab40a622b2223f488380931f0ea48dcaa6b14fc20ee2fff"
        }

        result = signer._validate_signature(queryObj)
        self.assertTrue(result)

    def test_validation_fail(self):
        """Should return false if url is signature is not matched"""
        queryObj = {
            "name": "dean",
            "age": "27",
            "intput_secret": "test_secret",
            "B02K_MAC": "random signature"
        }

        result = signer._validate_signature(queryObj)

        self.assertFalse(result)


class TestProcessSignedURL(unittest.TestCase):
    def test_process_URL(self):
        """Should process URL sucessfully"""
        splittedURL = SplitResult("http", "fsecure.com", "/", "", "")

        result = signer._process_signed_url(splittedURL, "Lebron James", "aaa")

        expectedRes = "http://fsecure.com/?firstname=Lebron&lastname=James&hash=91595c4c920d6624d9a5f738a64b6b81ab316d54a6428db1381a10e8f74a3a21"
        self.assertEqual(result, expectedRes)

    def test_customer_with_middle_name(self):
        """Should process URL sucessfully even when customer has middle name"""
        splittedURL = SplitResult("http", "fsecure.com", "/", "", "")

        result = signer._process_signed_url(splittedURL, "Lebron Goat James", "aaa")

        expectedRes = "http://fsecure.com/?firstname=Lebron&lastname=James&hash=91595c4c920d6624d9a5f738a64b6b81ab316d54a6428db1381a10e8f74a3a21"
        self.assertEqual(result, expectedRes)

    def test_customer_missing_name(self):
        """Should return error message if there is not enough information about customer name"""
        splittedURL = SplitResult("http", "fsecure.com", "/", "", "")

        result = signer._process_signed_url(splittedURL, "Lebron", "aaa")

        self.assertEqual(result, "Not enough customer's name information")


@patch('signer._validate_signature')
@patch('signer._process_signed_url')
class TestSignURL(unittest.TestCase):
    def setUp(self):
        os.environ[signer.INPUT_SECRET] = "inputsecret"
        os.environ[signer.OUTPUT_SECRET] = "outputsecret"

    def tearDown(self):
        del os.environ[signer.INPUT_SECRET]
        del os.environ[signer.OUTPUT_SECRET]

    def test_sign_url_successfully(self, _process_signed_url, _validate_signature):
        """Should output URL correctly"""
        # Setup
        _validate_signature.return_value = True
        _process_signed_url.return_value = urlBase + "firstname=Dean&lastname=Le&hash=abc123"

        # Call function
        result = signer.sign(urlBase + "B02K_CUSTNAME=DEAN%20LE&B02K_MAC=xyz")

        # Asertion
        self.assertEqual(result, urlBase + "firstname=Dean&lastname=Le&hash=abc123")

        self.assertTrue(_validate_signature.called)
        args, _ = _validate_signature.call_args
        self.assertEqual(args[0], {"B02K_CUSTNAME": "DEAN LE", "B02K_MAC": "xyz", "input_secret": "inputsecret"})

        self.assertTrue(_process_signed_url.called)
        args, _ = _process_signed_url.call_args
        self.assertEqual(args[0], SplitResult("https", "fsecure.com", "/", "B02K_CUSTNAME=DEAN%20LE&B02K_MAC=xyz", ""))
        self.assertEqual(args[1], "DEAN LE")
        self.assertEqual(args[2], "outputsecret")

    def test_sign_url_successfully_nonAscii_custname(self, _process_signed_url, _validate_signature):
        """Should output URL correctly even with non-ascii customer name"""
        # Setup
        _validate_signature.return_value = True
        _process_signed_url.return_value = urlBase + "firstname=V%C3%A4in%C3%B6&lastname=M%C3%A4ki&hash=abc123"

        # Call function
        result = signer.sign(urlBase + "B02K_CUSTNAME=V%C4IN%D6%20M%C4KI&B02K_MAC=xyz")

        # Asertion
        self.assertEqual(result, urlBase + "firstname=V%C3%A4in%C3%B6&lastname=M%C3%A4ki&hash=abc123")

        args, _ = _validate_signature.call_args
        self.assertEqual(args[0], {"B02K_CUSTNAME": "VÄINÖ MÄKI", "B02K_MAC": "xyz", "input_secret": "inputsecret"})

        args, _ = _process_signed_url.call_args
        self.assertEqual(args[0], SplitResult("https", "fsecure.com", "/", "B02K_CUSTNAME=V%C4IN%D6%20M%C4KI&B02K_MAC=xyz", ""))
        self.assertEqual(args[1], "VÄINÖ MÄKI")
        self.assertEqual(args[2], "outputsecret")

    def test_signature_missing(self, _process_signed_url, _validate_signature):
        """Should return 'Signature is missing' if there is no signature"""
        result = signer.sign(urlBase + "B02K_CUSTNAME=DEAN%20LE")

        self.assertEqual(result, "Signature is missing")
        self.assertFalse(_validate_signature.called)
        self.assertFalse(_process_signed_url.called)

    def test_sign_url_invalid_url(self, _process_signed_url, _validate_signature):
        """Should return 'Invalid URL' if cannot validate"""
        _validate_signature.return_value = False

        result = signer.sign(urlBase + "B02K_CUSTNAME=DEAN%20LE&B02K_MAC=xyz")

        self.assertEqual(result, "Invalid URL")
        args, _ = _validate_signature.call_args
        self.assertEqual(args[0], {"B02K_CUSTNAME": "DEAN LE", "B02K_MAC": "xyz", "input_secret": "inputsecret"})

        self.assertFalse(_process_signed_url.called)


if __name__ == '__main__':
    unittest.main()
