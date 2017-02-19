# Really Simple JSON Web Tokens

A simple Package for creating JSON Web Tokens that uses HMAC SHA256 to sign
signatures. Exposes a simple interface to allow you to create a simple token
that stores a user identifier. The Package is set up to allow extension and
the use of larger payloads.

For more information on JSON Web Tokens please see https://jwt.io

## Usage

### Get Token

```
<?php

use ReallySimpleJWT\Token;

$token = Token::getToken(1, 'secret', '2017-01-01 01:01:01', '127.0.0.1');
```

### Validate Token

```
<?php

use ReallySimpleJWT\Token;

$result = Token::validate('token', 'secret');
```

## Author

Rob Waller

Email: rdwaller1984@gmail.com

Twitter: @robdwaller 