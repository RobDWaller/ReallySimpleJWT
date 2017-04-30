# Really Simple JSON Web Tokens
[![Build Status](https://travis-ci.org/RobDWaller/ReallySimpleJWT.svg?branch=master)](https://travis-ci.org/RobDWaller/ReallySimpleJWT) [![codecov](https://codecov.io/gh/RobDWaller/ReallySimpleJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/RobDWaller/ReallySimpleJWT) [![StyleCI](https://styleci.io/repos/82379868/shield?branch=master)](https://styleci.io/repos/82379868) [![Latest Stable Version](https://poser.pugx.org/rbdwllr/reallysimplejwt/v/stable)](https://packagist.org/packages/rbdwllr/reallysimplejwt) [![Total Downloads](https://poser.pugx.org/rbdwllr/reallysimplejwt/downloads)](https://packagist.org/packages/rbdwllr/reallysimplejwt)

A simple package for creating JSON Web Tokens that uses HMAC SHA256 to sign
signatures. Exposes a simple interface to allow you to create a token that stores a user identifier. The package is set up to allow extension and the use of larger payloads.

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

### Advanced Usage

If you would like to access the token builder interface directly simply instantiate the TokenBuilder class.

As should be clear you can add as much to the token payload as you need.

```php
<?php

use ReallySimpleJWT\TokenBuilder;

$builder = new TokenBuilder();

$token = $builder->addPayload('key', 'value')
    ->addPayload('key', 'value')
    ->setSecret($secret)
    ->setExpiration($expiration)
    ->setIssuer($issuer)
    ->build();
```

In addition you can access the token validator interface directly too by instantiating the TokenValidator class.

```php
<?php

use ReallySimpleJWT\TokenValidator;

$validator = new TokenValidator;

$validator->splitToken('token string')
    ->validateExpiration()
    ->validateSignature('secret');
        
$payload = $validator->getPayload();

$header = $validator->getHeader();
```

## License

MIT

## Author

Rob Waller

Twitter: [@robdwaller](https://twitter.com/RobDWaller)