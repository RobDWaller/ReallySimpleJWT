# Really Simple JSON Web Tokens
[![Build Status](https://travis-ci.org/RobDWaller/ReallySimpleJWT.svg?branch=master)](https://travis-ci.org/RobDWaller/ReallySimpleJWT) [![codecov](https://codecov.io/gh/RobDWaller/ReallySimpleJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/RobDWaller/ReallySimpleJWT) [![StyleCI](https://styleci.io/repos/82379868/shield?branch=master)](https://styleci.io/repos/82379868)

A simple Package for creating JSON Web Tokens that uses HMAC SHA256 to sign
signatures. Exposes a simple interface to allow you to create a simple token
that stores a user identifier. The Package is set up to allow extension and
the use of larger payloads.

For more information on JSON Web Tokens please see https://jwt.io

## Usage

### Get Token

Call the get token method and pass in user identifier, key secret, expiration 
date time string and the token issuer.

Will return a token string on success and throw an exception on failure.

```php
<?php

use ReallySimpleJWT\Token;

$token = Token::getToken('userIdentifier', 'secret', 'dateTimeString', 'issuerIdentifier');
```

### Validate Token

Call the validate method, pass in your token string and the key secret. 

Will return boolean true on success and throw an exception on failure.

```php
<?php

use ReallySimpleJWT\Token;

$result = Token::validate('token', 'secret');
```

## License

MIT

## Author

Rob Waller

Twitter: @robdwaller 