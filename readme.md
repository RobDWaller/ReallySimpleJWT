# Really Simple JSON Web Tokens
[![Build Status](https://travis-ci.org/RobDWaller/ReallySimpleJWT.svg?branch=master)](https://travis-ci.org/RobDWaller/ReallySimpleJWT) [![codecov](https://codecov.io/gh/RobDWaller/ReallySimpleJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/RobDWaller/ReallySimpleJWT)

A simple Package for creating JSON Web Tokens that uses HMAC SHA256 to sign
signatures. Exposes a simple interface to allow you to create a simple token
that stores a user identifier. The Package is set up to allow extension and
the use of larger payloads.

For more information on JSON Web Tokens please see https://jwt.io

## Usage

### Get Token

Call the get token method and pass in user identifier, key secret, expiration 
date time string and the token issuer.

```php
<?php

use ReallySimpleJWT\Token;

$token = Token::getToken(1, 'secret', '2017-01-01 01:01:01', '127.0.0.1');
```

### Validate Token

Call the validate method, pass in your token string and the key secret. 

```php
<?php

use ReallySimpleJWT\Token;

$result = Token::validate('token', 'secret');
```

## Author

Rob Waller

Email: rdwaller1984@gmail.com

Twitter: @robdwaller 