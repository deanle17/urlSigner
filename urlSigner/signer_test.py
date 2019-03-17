import unittest
import signer
from urllib.parse import SplitResult
from unittest.mock import patch
import os


class TestValidateURL(unittest.TestCase):
    def test_validation_succeed(self):
        """Should return true if url is valid"""
        queryObj = {
            "name": "dean",
            "age": "27",
            "intput_secret": "test_secret",
            "B02K_MAC": "3d44edcfed6d58e99ab40a622b2223f488380931f0ea48dcaa6b14fc20ee2fff"
        }

        result = signer._validateSignature(queryObj)
        self.assertTrue(result)

    def test_validation_fail(self):
        """Should return false if url is signature is not matched"""
        queryObj = {
            "name": "dean",
            "age": "27",
            "intput_secret": "test_secret",
            "B02K_MAC": "random signature"
        }

        result = signer._validateSignature(queryObj)

        self.assertFalse(result)


class TestProcessSignedURL(unittest.TestCase):
    def test_process_URL(self):
        """Should process URL sucessfully"""
        splittedURL = SplitResult("http", "fsecure.com", "/", "", "")

        result = signer._processSignedURL(splittedURL, "Lebron James", "aaa")

        expectedRes = "http://fsecure.com/?firstname=Lebron&lastname=James&hash=91595c4c920d6624d9a5f738a64b6b81ab316d54a6428db1381a10e8f74a3a21"
        self.assertEqual(result, expectedRes)

    def test_process_URL_middle_name(self):
        """Should process URL sucessfully even when customer has middle name"""
        splittedURL = SplitResult("http", "fsecure.com", "/", "", "")

        result = signer._processSignedURL(
            splittedURL, "Lebron Goat James", "aaa")

        expectedRes = "http://fsecure.com/?firstname=Lebron&lastname=James&hash=91595c4c920d6624d9a5f738a64b6b81ab316d54a6428db1381a10e8f74a3a21"
        self.assertEqual(result, expectedRes)


@patch('signer._validateSignature')
@patch('signer._processSignedURL')
class TestSignURL(unittest.TestCase):
    def setUp(self):
        os.environ["INPUT_SECRET"] = "inputsecret"
        os.environ["OUTPUT_SECRET"] = "outputsecret"

    def tearDown(self):
        del os.environ["INPUT_SECRET"]
        del os.environ["OUTPUT_SECRET"]

    def test_sign_url_successfully(self, _processSignedURL, _validateSignature):
        """Should output URL correctly"""
        # Setup
        _validateSignature.return_value = True
        _processSignedURL.return_value = "https://fsecure.com/firstname=Dean&lastname=Le&hash=abc123"

        # Call function
        result = signer.sign("https://fsecure.com/?B02K_CUSTNAME=DEAN%20LE")

        # Asertion
        self.assertEqual(
            result, "https://fsecure.com/firstname=Dean&lastname=Le&hash=abc123")

        args, _ = _validateSignature.call_args

        self.assertEqual(
            args[0], {"B02K_CUSTNAME": "DEAN LE", "input_secret": "inputsecret"})

        args, _ = _processSignedURL.call_args
        self.assertEqual(args[0], SplitResult(
            "https", "fsecure.com", "/", "B02K_CUSTNAME=DEAN%20LE", ""))
        self.assertEqual(args[1], "DEAN LE")
        self.assertEqual(args[2], "outputsecret")

    def test_sign_url_invalid_url(self, _processSignedURL, _validateSignature):
        """Should return 'Invalid URL' if cannot validate"""
        _validateSignature.return_value = False

        result = signer.sign("https://fsecure.com/?B02K_CUSTNAME=DEAN%20LE")

        self.assertEqual(result, "Invalid URL")
        args, _ = _validateSignature.call_args
        self.assertEqual(
            args[0], {"B02K_CUSTNAME": "DEAN LE", "input_secret": "inputsecret"})

        self.assertFalse(_processSignedURL.called)


if __name__ == '__main__':
    unittest.main()
