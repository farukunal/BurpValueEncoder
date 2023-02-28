# BurpValueEncoder
The Burp extender "Value Encoder" is a powerful extender that can be used to enhance the functionality of Burp Suite Pro during web application security testing. One of the main features of this extension is its ability to encode any data such as base64, URL, ascii Hex encoding anywhere in Burp, by detecting the start and end point of specific flags.

The "Value Encoder" extension can detect the start and end point of the flags _base64, _url, and _asciiHex, and encode the data in the respective formats. This is particularly useful when dealing with the encoded data in HTTP requests, as it allows testers to easily decode the data, append the payload, and encode the data again in BASE64 format before sending it to the server.

Using flags _base64, _url, and _asciiHex:

	_base64'Your Value'_base64
	_url'Your Value'_url
	_asciiHex'Your Value'_asciiHex
