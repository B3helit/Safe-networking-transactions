Safe network requests and responses using HMAC-SHA512, this project is only a POC, it insures integrity of the message and authentication of origin, but not confidentiality. The code in client is C++, and the server is as a simple Python.
The client requires including openssl in this project. We are using openssl library for encryption and decryption. And for the server you'll need to install the library flask.
The project assumes an existent known shared key between only the server and this client.
