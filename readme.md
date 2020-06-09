# Really Simple JSON Web Tokens
[![Actions Status](https://github.com/robdwaller/reallysimplejwt/workflows/ci/badge.svg)](https://github.com/robdwaller/reallysimplejwt/actions) [![codecov](https://codecov.io/gh/RobDWaller/ReallySimpleJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/RobDWaller/ReallySimpleJWT) [![Infection MSI](https://badge.stryker-mutator.io/github.com/RobDWaller/ReallySimpleJWT/master)](https://infection.github.io) [![StyleCI](https://styleci.io/repos/82379868/shield?branch=master)](https://styleci.io/repos/82379868) [![Latest Stable Version](https://poser.pugx.org/rbdwllr/reallysimplejwt/v/stable)](https://packagist.org/packages/rbdwllr/reallysimplejwt) ![PHP Version Support](https://img.shields.io/travis/php-v/RobDWaller/ReallySimpleJWT/master) [![Total Downloads](https://poser.pugx.org/rbdwllr/reallysimplejwt/downloads)](https://packagist.org/packages/rbdwllr/reallysimplejwt)

A simple PHP library for creating JSON Web Tokens that uses HMAC SHA256 to sign signatures. For basic usage the library exposes a static interface to allow developers to create a token that stores a user identifier and expiration time.

The library is also open to extension, developers can define their own encoding standard, their own secret validation, set all the [RFC standard](https://tools.ietf.org/html/rfc7519) JWT claims, and set their own private claims.

You can easily integrate ReallySimpleJWT with PSR-7 / PSR-15 compliant frameworks such as [Slim PHP](https://packagist.org/packages/slim/slim) with the [PSR-JWT middleware library](https://github.com/RobDWaller/psr-jwt). Please read the [framework integration documentation](#framework-integration-with-psr-jwt-middleware) to learn more.

If you need to read tokens in the browser please take a look at our JavaScript / Typescript library [RS-JWT](https://github.com/RobDWaller/rs-jwt).

## Contents

- [What is a JSON Web Token?](#what-is-a-json-web-token)
- [Setup](#setup)
- [Basic Usage](#basic-usage)
    - [Create Token](#create-token)
    - [Validate Token](#validate-token)
    - [Get Header and Payload Claims Data](#get-header-and-payload-claims-data)
    - [Build and Parse Factory Methods](#build-and-parse-factory-methods)
- [Advanced Usage](#advanced-usage)
    - [Create Custom Token](#create-custom-token)
    - [Access the Token](#access-the-token)
    - [Parse and Validate Token](#parse-and-validate-token)
    - [Access Token Claims Data](#access-token-claims-data)
    - [Custom Encoding](#custom-encoding)
- [Error Messages and Codes](#error-messages-and-codes)
- [Token Security](#token-security)
    - [Signature Secret](#signature-secret)
    - [Custom Secrets](#custom-secrets)
- [Framework Integration With PSR-JWT Middleware](#framework-integration-with-psr-jwt-middleware)
- [Browser Integration With RS-JWT](#browser-integration-with-rs-jwt)

## What is a JSON Web Token?

JSON Web Tokens is a standard for creating URL friendly access tokens that assert claims about a user or system.

A token is broken down into three parts; the header, the payload and the signature; with each part separated by a dot. Each part is encoded using the base64URL standard, see the [RFC](https://tools.ietf.org/html/rfc4648#page-7).

An example JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

The header and payload are both encoded JSON strings that contain a number of claims:

```javascript
// Example Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Example Payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

A claim is a key value pair, eg `"typ": "JWT"`, please read [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4) to learn more about JSON Web Token claims.

Token security is achieved via the signature which is made up of the header, payload and a secret known only to the token author. This information is hashed and then base64URL encoded.

If a malicious user attempts to edit the header or payload claims they will be unable to replicate the signature so long as you use a strong secret. See [Token Security](#token-security) for more information on this.

## Setup

To install this package you will need to install [Composer](https://getcomposer.org/) and then run `composer init`. Once this is done you can install the package via the command line or by editing the composer.json file created by the `composer init` command.

Finally you will need to reference the composer autoloader in your PHP code, `require 'vendor/autoload.php';`. The location of the autoload file will differ dependent on where your code is run. Also you will not need to reference the autoload file if you are using a framework like Laravel or Symfony.

**Install via Composer on the command line:**

```bash
composer require rbdwllr/reallysimplejwt
```

**Install via the composer.json file:**

Add the following to your composer.json file:

```javascript
"require": {
    "rbdwllr/reallysimplejwt": "^2.0"
}
```

Then run:

```bash
composer update
```

## Basic Usage

For basic usage the library exposes a set of static methods via the `ReallySimpleJWT\Token` class which allow a developer to create and validate basic JSON Web Tokens.

### Create Token

Call the `create()` static method and pass in a user identifier, a secret, an expiration date time number and the token issuer.

This will return a token string on success and throw a `ReallySimpleJWT\Exception\ValidateException` on failure.

```php
use ReallySimpleJWT\Token;

require 'vendor/autoload.php';

$userId = 12;
$secret = 'sec!ReT423*&';
$expiration = time() + 3600;
$issuer = 'localhost';

$token = Token::create($userId, $secret, $expiration, $issuer);
```

To create a more customised token developers can use the `customPayload()` method. This allows the creation of a token based on an array of key value pairs which represent the payload claims.

```php
use ReallySimpleJWT\Token;

require 'vendor/autoload.php';

$payload = [
    'iat' => time(),
    'uid' => 1,
    'exp' => time() + 10,
    'iss' => 'localhost'
];

$secret = 'Hello&MikeFooBar123';

$token = Token::customPayload($payload, $secret);
```

On success the `customPayload()` method will return a JWT token string and on failure it will throw an exception.

### Validate Token

To validate a JSON web token call the `validate()` static method, pass in the token string and the secret. The validate method checks the token structure is correct, the signature is valid, the expiration time has not expired and the not before time has elapsed.

It will return true on success and false on failure.

```php
use ReallySimpleJWT\Token;

require 'vendor/autoload.php';

$token = 'aaa.bbb.ccc';
$secret = 'sec!ReT423*&';

$result = Token::validate($token, $secret);
```

### Get Header and Payload Claims Data

To retrieve the token claims data from the header or payload call the `getHeader()` and or `getPayload()` static methods.

Both methods will return an associative array on success and throw an exception on failure.

```php
use ReallySimpleJWT\Token;

require 'vendor/autoload.php';

$token = 'aaa.bbb.ccc';
$secret = 'sec!ReT423*&';

// Return the header claims
Token::getHeader($token, $secret);

// Return the payload claims
Token::getPayload($token, $secret);
```

### Build and Parse Factory Methods

The `ReallySimpleJWT\Token` class also provides two factory methods to gain access to the core `ReallySimpleJWT\Build` and `ReallySimpleJWT\Parse` classes. These classes allow you to build custom tokens and parse and validate tokens as you see fit.

```php
Token::builder(); // Returns an instance of ReallySimpleJWT\Build

Token::parser($token, $secret); // Returns an instance of ReallySimpleJWT\Parse
```

## Advanced Usage

To create customised JSON Web Tokens developers need to access the `ReallySimpleJWT\Build` and `ReallySimpleJWT\Parse` classes directly.

### Create Custom Token

The `ReallySimpleJWT\Build` class allows you to create a completely unique JSON Web Token. It has helper methods for all the [RFC](https://tools.ietf.org/html/rfc7519#section-4) defined header and payload claims. For example, the `setIssuer()` method will add the `iss` claim to the token payload.

The class also allows developers to set custom header and payload claims via the `setHeaderClaim()` and `setPayloadClaim()` methods.

The methods can be chained together and when the `build()` method is called the token will be generated and returned within a `ReallySimpleJWT\Jwt` object.

```php
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;

require 'vendor/autoload.php';

$build = new Build('JWT', new Validate(), new Encode());

$token = $build->setContentType('JWT')
    ->setHeaderClaim('info', 'foo')
    ->setSecret('!secReT$123*')
    ->setIssuer('localhost')
    ->setSubject('admins')
    ->setAudience('https://google.com')
    ->setExpiration(time() + 30)
    ->setNotBefore(time() - 30)
    ->setIssuedAt(time())
    ->setJwtId('123ABC')
    ->setPayloadClaim('uid', 12)
    ->build();
```

### Access the Token

A `ReallySimpleJWT\Jwt` object is returned when a developer calls the `build()` method on the `ReallySimpleJWT\Build` class. The Jwt class offers two methods `getToken()` and `getSecret()`. The former returns the generated JSON Web Token and the latter returns the secret used for the token signature.

To parse a JSON Web Token via the `ReallySimpleJWT\Parse` class a developer must first create a new `ReallySimpleJWT\Jwt` object by injecting the token and secret.

```php
use ReallySimpleJWT\Jwt;

require 'vendor/autoload.php';

$token = 'aaa.bbb.ccc';
$secret = '!secReT$123*';

$jwt = new Jwt($token, $secret);

// Return the token
$jwt->getToken();

// Return the secret
$jwt->getSecret();
```

### Parse and Validate Token

The `ReallySimpleJWT\Parse` class allows a developer to parse and validate a JSON Web Token. Four validation methods are available which can all be chained:

- `validate()` confirms the structure of the token and the validity of the signature.
- `validateExpiration()` confirms the token expiration claim (`exp`) has not expired.
- `validateNotBefore()` confirms the token not before claim (`nbf`) has elapsed.
- `validateAudience()` confirms the token audience claim (`aud`) matches what is expected.
- `validateAlgorithm()` confirms the token algorithm claim (`alg`) matches what is expected and is valid (See: [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html)).

Each validation method will throw a `ReallySimpleJWT\Exception\ValidateException` if there is anything wrong with the supplied token.

The `parse()` method which should be called after validation is complete will decode the JSON Web Token. It will then return the result as a `ReallySimpleJWT\Parsed` object. This will provide access to the claims data the token holds in the header and the payload.

```php
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;

require 'vendor/autoload.php';

$token = 'aaa.bbb.ccc';
$secret = '!secReT$123*';

$jwt = new Jwt($token, $secret);

$parse = new Parse($jwt, new Validate(), new Encode());

$parsed = $parse->validate()
    ->validateExpiration()
    ->validateNotBefore()
    ->validateAudience('https://example.com')
    ->validateAudience('https://test.com')
    ->parse();

// Return the token header claims as an associative array.
$parsed->getHeader();

// Return the token payload claims as an associative array.
$parsed->getPayload();
```

### Access Token Claims Data

The `ReallySimpleJWT\Parsed` class is returned when a developer calls the `parse()` method on the `ReallySimpleJWT\Parse` class.

It provides a number of helper methods to gain access to the token claim data. A developer can call the `getHeader()` and `getPayload()` methods to gain access to the respective claim data as associative arrays.

Alternatively a developer can call one of the [RFC](https://tools.ietf.org/html/rfc7519#section-4) compliant claim methods:

**Header**
- `getAlgorithm()`
- `getType()`
- `getContentType()`

**Payload**
- `getIssuer()`
- `getSubject()`
- `getAudience()`
- `getExpiration()`
- `getNotBefore()`
- `getIssuedAt()`
- `getJwtId()`
- `getExpiresIn()`
- `getUsableIn()`

### Custom Encoding

By default this library hashes and encodes the JWT signature via `hash_hmac()` using the sha256 algorithm. If a developer would like to use a customised form of encoding they just need to generate a custom encode class which complies with the `ReallySimpleJWT\Interfaces\Encoder` interface.

```php
interface EncodeInterface
{
    public function getAlgorithm(): string;

    public function encode(string $toEncode): string;

    public function decode(string $toDecode): string;

    public function signature(string $header, string $payload, string $secret): string;
}
```

## Error Messages and Codes

The ReallySimpleJWT library will in a number of situations throw exceptions to highlight problems when creating and parsing JWT tokens. The error codes, messages and their explanations are below.

| Code | Message                           | Explanation                                |
|:----:| --------------------------------- | ------------------------------------------ |
| 1    | Token is invalid.                 | Token must have three parts separated by dots. |
| 2    | Audience claim does not contain provided StringOrURI.        | The aud claim must contain the provided string or URI string provided. |
| 3    | Signature is invalid.             | Signature does not match header / payload content. Could not replicate signature with provided header, payload and secret. |
| 4    | Expiration claim has expired.     | The exp claim must be a valid date time number in the future. |
| 5    | Not Before claim has not elapsed. | The nbf claim must be a valid date time number in the past. |
| 6    | Expiration claim is not set.      | Attempt was made to validate an Expiration claim which does not exist. |
| 7    | Not Before claim is not set.      | Attempt was made to validate a Not Before claim which does not exist. |
| 8    | Invalid payload claim.            | Payload claims must be key value pairs of the format string: mixed. |
| 9    | Invalid secret.                   | Must be 12 characters in length, contain upper and lower case letters, a number, and a special character `*&!@%^#$`` |
| 10   | Invalid Audience claim.           | The aud claim can either be a string or an array of strings nothing else. |
| 11   | Audience claim is not set.      | Attempt was made to validate an Audience claim which does not exist. |
| 12   | Algorithm claim is not valid.   | Algorithm should be a valid Digital Signature or MAC Algorithm, or none. See RFC 7518. |
| 13   | Algorithm claim is not set.      | Attempt was made to validate an Algorithm claim which does not exist. |

## Token Security

The JWT [RFC 7519](https://tools.ietf.org/html/rfc7519#section-7) allows for the creation of tokens without signatures and without secured / hashed signatures. The ReallySimpleJWT library however imposes security by default as there is no logical reason not to. All created tokens must have a signature and a strong secret, but the library will validate tokens without a secret or a strong secret. The library will not validate tokens without a signature.

It is possible to edit and enhance the implementation of the signature and its security level by creating a custom encode class that implements the `ReallySimpleJWT\Interfaces\Encode` interface, or a custom secret class which implements the `ReallySimpleJWT\Interfaces\Secret` interface. See sections [Custom Encoding](#custom-encoding) and [Custom Secrets](#custom-secrets)

### Signature Secret

This JWT library imposes strict secret security as follows: the secret must be at least 12 characters in length; contain numbers; upper and lowercase letters; and one of the following special characters `*&!@%^#$`.

```php
// Bad Secret
secret123

// Good Secret
sec!ReT423*&
```

The reason for this is that there are lots of [JWT Crackers](https://github.com/lmammino/jwt-cracker) available meaning weak secrets are easy to crack thus rendering the security JWT offers useless.

### Custom Secrets

While we advise **strongly against** using weak secrets for JWT signatures we do accept there are systems on the 'internets' which for one reason or another impose weak secrets on developers.

You can setup custom secret validation by creating your own secret class which implements the `ReallySimpleJWT\Interfaces\Secret` interface. You can then pass this custom secret class to the `ReallySimpleJWT\Build` class.

```php
<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Secret;

class CustomSecret implements Secret
{
    public function validate(string $secret): bool
    {
        // Please do not copy this code, it is an example of weak secret validation.
        return (bool) preg_match('/[a-z]+/', $secret);
    }
}

// Create JWT Builder with Custom Secret Class.
$build = new Build(
    'JWT', 
    new Validate(), 
    new CustomSecret(), 
    new Encode()
);
```

## Framework Integration With PSR-JWT Middleware

You can easily integrate ReallySimpleJWT with [PSR-7 / PSR-15](https://www.php-fig.org/psr/psr-15/) compliant frameworks such as [Slim PHP](https://packagist.org/packages/slim/slim) and Zend Expressive by using the [PSR-JWT library](https://github.com/RobDWaller/psr-jwt).

For example integration with Slim PHP only requires a few lines of code:

```php
// Can be added to any routes file in Slim, often index.php.
require '../../vendor/autoload.php';

$app->get('/jwt', function (Request $request, Response $response) {
    $response->getBody()->write("JSON Web Token is Valid!");

    return $response;
})->add(\PsrJwt\Factory\JwtAuth::middleware('Secret123!456$', 'jwt', 'Authentication Failed'));
```

Please read the [PSR-JWT documentation](https://github.com/RobDWaller/psr-jwt) to learn more about integration options for ReallySimpleJWT.

## Browser Integration With RS-JWT

When you create JSON Web Tokens you may wish to read some of the information contained in the header and payload claims in the browser.

If you do, we have an NPM packages for that called [RS-JWT](https://github.com/RobDWaller/rs-jwt).

**Install:**
```bash
npm install --save rs-jwt
```

**Usage:**
```js
import { parseJwt } from 'rs-jwt'

const result = parseJwt('json.web.token')

// Return the header claims as an object.
const header = result.getHeader()

// Access the type claim.
console.log(header.typ)

// Return the payload claims as an object.
const payload = result.getPayload()

// Access the expiry claim.
console.log(payload.exp)
```

For more information see the project [README](https://github.com/RobDWaller/rs-jwt/blob/master/README.md) or visit the [NPM Page](https://www.npmjs.com/package/rs-jwt).

## License

MIT

## Author

Rob Waller

Twitter: [@robdwaller](https://twitter.com/RobDWaller)
