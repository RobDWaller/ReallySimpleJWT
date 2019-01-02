# Really Simple JSON Web Tokens
[![Build Status](https://travis-ci.org/RobDWaller/ReallySimpleJWT.svg?branch=master)](https://travis-ci.org/RobDWaller/ReallySimpleJWT) [![codecov](https://codecov.io/gh/RobDWaller/ReallySimpleJWT/branch/master/graph/badge.svg)](https://codecov.io/gh/RobDWaller/ReallySimpleJWT) [![StyleCI](https://styleci.io/repos/82379868/shield?branch=master)](https://styleci.io/repos/82379868) [![Latest Stable Version](https://poser.pugx.org/rbdwllr/reallysimplejwt/v/stable)](https://packagist.org/packages/rbdwllr/reallysimplejwt) [![Total Downloads](https://poser.pugx.org/rbdwllr/reallysimplejwt/downloads)](https://packagist.org/packages/rbdwllr/reallysimplejwt)

A simple PHP Library for creating JSON Web Tokens that uses HMAC SHA256 to sign
signatures. Exposes a simple static interface to allow developers to create a token that stores a user identifier and expiration time.

The library is also open to extension, developers can define their own encoding standard, set all the [RFC standard](https://tools.ietf.org/html/rfc7519) JWT claims and set their own private claims.  

## Contents

- [What is a JSON Web Token?](#what-is-a-json-web-token)
- [Setup](#setup)
- [Basic Usage](#basic-usage)
    - [Create Token](#create-token)
    - [Validate Token](#validate-token)
    - [Get Header and Payload Claims Data](#get-header-and-payload-claims-data)
    - [Factory Methods](#factory-methods)
- [Advanced Usage](#advanced-usage)
    - [Create Custom Token](#create-custom-token)
    - [Access the Token](#access-the-token)
    - [Advanced Token Validation](#advanced-token-validation)
    - [Access Token Claims Data](#access-token-claims-data)
    - [Customised Encoding](#customised-encoding)
- [Secret Security](#secret-security)
- [Version One Support](#version-one-support)

## What is a JSON Web Token?

JSON Web Tokens is a standard for creating URL friendly access tokens that assert claims about a user or system.

A token is broken down into three parts; the header, the payload and the signature; with each part separated by a dot. Each part is encoded using the base64url standard, see the [RFC](https://tools.ietf.org/html/rfc4648#page-7).

An example JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

The header and payload are both encoded JSON strings that contain a number of claims:

```javascript
// Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

A claim is a key value pair, eg `"typ": "JWT"`, please read [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4) to learn more about JSON Web Token claims.

Token security is achieved via the signature which is made up of the header, payload and a secret known only to the token author. This information is hashed and then base64url encoded.
If a malicious user attempts to edit the header or payload claims they will be unable to replicate the signature so long as you use a strong key. See [Secret Security] for more information on this.

## Setup

Via Composer on the command line:

```bash
composer require rbdwllr/reallysimplejwt
```

Via Composer.json:

```javascript
"require": {
    "rbdwllr/reallysimplejwt": "^2.0"
}
```

## Basic Usage

For basic usage the library exposes a set of static methods via the `ReallySimpleJWT\Token` class. This allows a developer to create and validate a token, with a user identifier and a token expiration time, via two method calls.

### Create Token

Call the get token static method and pass in a user identifier, a secret, an expiration date time number and the token issuer.

This will return a token string on success and throw an exception on failure.

```php
use ReallySimpleJWT\Token;

$userId = 12;
$secret = 'sec!ReT423*&'
$expiration = time() + 3600;
$issuer = 'localhost'

$token = Token::create($userId, $secret, $expiration, $issuer);
```

### Validate Token

To validate a JSON web token call the validate static method, pass in the token string and the secret.

The validate method checks the token structure is correct, the signature is valid and the expiration time has not elapsed.

It will return true on success and false on failure.

```php
use ReallySimpleJWT\Token;

$token = 'aaa.bbb.ccc';
$secret = 'sec!ReT423*&'

$result = Token::validate($token, $secret);
```

### Get Header and Payload Claims Data

To retrieve the token claims data from the header or payload call the `getHeader()` and or `getPayload()` static methods.

Both methods will return an associative array on success and throw an exception on failure.

```php
use ReallySimpleJWT\Token;

$token = 'aaa.bbb.ccc';
$secret = 'sec!ReT423*&'

// Return the header claims
Token::getHeader($token, $secret);

// Return the payload claims
Token::getPayload($token, $secret);
```

### Factory Methods

The `ReallySimpleJWT\Token` class also provides two Factory methods to gain
access to the core `ReallySimpleJWT\Build` and `ReallySimpleJWT\Parse` classes.

```php
Token::builder(); // Returns an instance of ReallySimpleJWT\Build

Token::parser($token, $secret); // Returns an instance of ReallySimpleJWT\Parse
```

## Advanced Usage

To create customised JSON Web Tokens developers need to access the `ReallySimpleJWT\Build` and `ReallySimpleJWT\Parse` classes directly.

### Create Custom Token

The `ReallySimpleJWT\Build` class allows you to create a completely unique JSON Web Token. It has helper methods for all the RFC defined header and payload claims. The `setIssuer()` method will add the `iss` claim to the token header.

The class also allows developers to set custom header and payload claims via the `setHeaderClaim()` and `setPrivateClaim()` methods.

The methods can be chained together and when the `build()` method is called the token will be generated and returned within a `ReallySimpleJWT\Jwt` object.

```php
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;

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
    ->setPrivateClaim('uid', 12)
    ->build();
```

### Access the Token

The `ReallySimpleJWT\Jwt` is returned when a developer calls the `build()` method on the `ReallySimpleJWT\Build` class. The Jwt class offers two methods `getToken()` and `getSecret()`. The former returns the generated JSON Web Token and the latter returns the secret used for the token signature.

To parse a JSON Web Token via the `ReallySimpleJWT\Parse` class a developer must first create a new `ReallySimpleJWT\Jwt` object by injecting the token and secret.

```php
use ReallySimpleJWT\Jwt;

$token = 'aaa.bbb.ccc';
$secret = '!secReT$123*';

$jwt = new Jwt($token, $secret);

// Return the token
$jwt->getToken();

// Return the secret
$jwt->getSecret();
```

### Advanced Token Validation

The `ReallySimpleJWT\Parse` class allows a developer to parse and validate a JSON Web Token. Three validation methods are available which can all be chained:

- `validate()` confirms the structure of the token and the validity of the signature.
- `validateExpiration()` confirms the token expiration claim has not elapsed.
- `validateNotBefore()` confirms the token not before claim has elapsed.

Each validation method will throw a `ReallySimpleJWT\Exception\ValidateException` if there is anything wrong with the supplied token.

The `parse()` method which should be called after validation is complete will decode the JSON Web Token. It will then return the result as a `ReallySimpleJWT\Parsed` object. This will provide access to the claim data the token holds in the header and the payload.

```php
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;

$token = 'aaa.bbb.ccc';
$secret = '!secReT$123*';

$jwt = new Jwt($token, $secret);

$parse = new Parse($jwt, new Validate(), new Encode());

$parsed = $parse->validate()
    ->validateExpiration()
    ->validateNotBefore()
    ->parse();

// Return the token header claims as an associative array.
$parsed->getHeader();

// Return the token payload claims as an associative array.
$parsed->getPayload();
```

### Access Token Claims Data

The `ReallySimpleJWT\Parsed` class is returned when a developer calls the `parse()` method on the `ReallySimpleJWT\Parse` class.

It provides a number of helper methods to gain access to the token claim data. A developer can call the `getHeader()` and `getPayload()` methods to gain access to the respective claim data as associative arrays.

Alternatively a developer can call one of the RFC compliant claim methods:

**Header**
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

### Customised Encoding

By default this library hashes and encodes the JWT signature via `hash_hmac()` using the sha256 algorithm. If a developer would like to use a customised form of encoding they just need to generate a custom encode class which complies with the `ReallySimpleJWT\Interfaces\EncodeInterface`.

```php
interface EncodeInterface
{
    public function getAlgorithm(): string;

    public function encode(string $toEncode): string;

    public function decode(string $toDecode): string;

    public function signature(string $header, string $payload, string $secret): string;
}
```

## Secret Key Security

This JWT library imposes strict secret security as follows: the secret must be at least 12 characters in length; contain numbers; upper and lowercase letters; and the one of the following special characters `*&!@%^#$`.

```php
// Bad Secret
secret123

// Good Secret
sec!ReT423*&
```

The reason for this is that there are lots of [JWT Crackers](https://github.com/lmammino/jwt-cracker) available meaning weak secrets are easy to crack thus rendering the security JWT offers useless.

## Version One Support

Support for version one of this library will continue until July 2019. No new features will be added to the version, just bug fixes and security patches.

## License

MIT

## Author

Rob Waller

Twitter: [@robdwaller](https://twitter.com/RobDWaller)
