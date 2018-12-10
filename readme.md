# Really Simple JSON Web Tokens
[![Build Status](https://travis-ci.org/RobDWaller/ReallySimpleJWT.svg?branch=master)](https://travis-ci.org/RobDWaller/ReallySimpleJWT) [![codecov](https://codecov.io/gh/RobDWaller/ReallySimpleJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/RobDWaller/ReallySimpleJWT) [![StyleCI](https://styleci.io/repos/82379868/shield?branch=master)](https://styleci.io/repos/82379868) [![Latest Stable Version](https://poser.pugx.org/rbdwllr/reallysimplejwt/v/stable)](https://packagist.org/packages/rbdwllr/reallysimplejwt) [![Total Downloads](https://poser.pugx.org/rbdwllr/reallysimplejwt/downloads)](https://packagist.org/packages/rbdwllr/reallysimplejwt)

A simple package for creating JSON Web Tokens that uses HMAC SHA256 to sign
signatures. Exposes a simple interface to allow you to create a token that stores a user identifier. The package is set up to allow extension and the use of larger payloads.

## What is a JSON Web Token?

JSON Web Tokens is a standard for creating URL friendly access tokens that assert claims about a user or system. They are broken down into three parts; the header, the payload and the signature; with each part separated by a dot.

For example:

```
aaa.bbb.ccc
```

Security is achieved via the signature which is made up of the header, payload and a secret known only to the token author.

For more information on JSON Web Tokens please see https://jwt.io

## Usage

### Setup

via composer: 

```bash 
composer require rbdwllr/reallysimplejwt
``` 

### Get Token

Call the get token method and pass in user identifier, key secret, expiration
date time string and the token issuer.

Will return a token string on success and throw an exception on failure.

```php
<?php

use ReallySimpleJWT\Token;

$token = Token::getToken('userIdentifier', 'secret', 'dateTimeString' | 'dateTimeNumber', 'issuerIdentifier');
```

**Expiration Time Note:** It was [pointed out](https://github.com/RobDWaller/ReallySimpleJWT/issues/13) that the expiration date does not comply with the [JWT RFC](https://tools.ietf.org/html/rfc7519#section-4.1.4). It should output a date time number and not a date time string. eg `exp: 1529495956` not `exp: '2018-06-20 11:59:16'`.

This has been fixed, but to aid backwards compatibility when generating a token you can set the expiration as a date time number or a date time string. The token will now always output with a date time number.

### Validate Token

Call the validate method, pass in your token string and the key secret.

Will return boolean true on success and throw an exception on failure.

```php
<?php

use ReallySimpleJWT\Token;

$result = Token::validate('token', 'secret');
```

### Get Payload

To retrieve the token payload call the `getPayload()` method.

Will return a JSON string on success and throw an exception on failure.

```php
use ReallySimpleJWT\Token;

$result = Token::getPayload('token');
```

## Advanced Usage

If you would like to access the token builder interface directly simply instantiate the TokenBuilder class.

As should be clear you can add as much to the token payload as you need.

```php
<?php

use ReallySimpleJWT\TokenBuilder;

$builder = new TokenBuilder();

$token = $builder->addPayload(['key' => 'foo', 'value' => 'bar'])
    ->addHeader(['key' => 'baz', 'value' => 'qux'])
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

## Secret Key Security

This JWT generator imposes secret security as follows: the secret must be at least 12 characters in length; contain numbers; upper and lowercase letters; and the one of the following special characters `*&!@%^#$`.

```php
// Bad Secret
secret123

// Good Secret
sec!ReT423*&
```

The reason for this is that there are lots of [JWT Crackers](https://github.com/lmammino/jwt-cracker) available meaning weak secrets are easy to crack thus rendering the security JWT offers useless.

## License

MIT

## Author

Rob Waller

Twitter: [@robdwaller](https://twitter.com/RobDWaller)
