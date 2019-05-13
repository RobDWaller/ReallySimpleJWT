<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use ReallySimpleJWT\Build;
use ReflectionMethod;

class ParseTest extends TestCase
{
    public function testParse()
    {
        $parse = new Parse(new JWT('Hello', 'secret'), new Validate(), new Encode());

        $this->assertInstanceOf(Parse::class, $parse);
    }

    public function testParseParse()
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, '127.0.0.1'), 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parsed::class, $parse->parse());
    }

    public function testParseIssuer()
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $result = $parse->parse();

        $this->assertSame('localhost', $result->getPayload()['iss']);
    }

    public function testParseSplitToken()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'splitToken');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($result[0], 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
        $this->assertSame($result[1], 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ');
        $this->assertSame($result[2], 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    }

    public function testParseGetPayload()
    {
        $token = new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56');

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getPayload');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame(explode('.', $token->getToken())[1], $result);
    }

    public function testParseGetHeader()
    {
        $token = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s', 'foo1234He$$llo56');

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getHeader');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame(explode('.', $token->getToken())[0], $result);
    }

    public function testParseValidate()
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validate());
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Token is invalid.
     * @expectedExceptionCode 1
     */
    public function testParseValidateInvalidStructure()
    {
        $parse = new Parse(
            new Jwt('hello', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $parse->validate();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Signature is invalid.
     * @expectedExceptionCode 3
     */
    public function testParseValidateBadTokenGoodStructure()
    {
        $parse = new Parse(
            new Jwt('hello.hello.hello', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $parse->validate();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Signature is invalid.
     * @expectedExceptionCode 3
     */
    public function testParseValidateInvalidSignature()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbT', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $parse->validate();
    }

    public function testGetSignature()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getSignature');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame('--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s', $result);
    }

    public function testParseValidateExpiration()
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'Hoo1234%&HePPo99', time() + 300, 'localhost'), 'Hoo1234%&HePPo99'),
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateExpiration());
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Expiration claim has expired.
     * @expectedExceptionCode 4
     */
    public function testParseValidateExpirationInvalid()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.FruqGMjzi7Ql7a8WJeMz6f6G5UeUQcy5kauLmeO8Ksc', 'Hoo1234%&HePPo99'),
            new Validate,
            new Encode()
        );

        $parse->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Expiration claim is not set.
     * @expectedExceptionCode 6
     */
    public function testParseValidateExpirationInvalidTwo()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s', 'Hoo1234%&HePPo99'),
            new Validate,
            new Encode()
        );

        $parse->validateExpiration();
    }

    public function testGetExpiration()
    {
        $timestamp = time() + 300;

        $parse = new Parse(
            new Jwt(Token::create(1, 'Hoo1234%&HePPo99', $timestamp, 'localhost'), 'Hoo1234%&HePPo99'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getExpiration');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($timestamp, $result);
    }

    public function testGetNotBefore()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $time = time() - 10;

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore($time)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getNotBefore');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($time, $result);
    }

    public function testParseValidateNotBefore()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore(time() - 10)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateNotBefore());
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Not Before claim has not elapsed.
     * @expectedExceptionCode 5
     */
    public function testParseValidateNotBeforeInvalid()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore(time() + 100)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $parse->validateNotBefore();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Not Before claim is not set.
     * @expectedExceptionCode 7
     */
    public function testParseValidateNotBeforeNotSet()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setExpiration(time() + 100)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $parse->validateNotBefore();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Expiration claim is not set.
     * @expectedExceptionCode 6
     */
    public function testParseValidateExpirationNotSet()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore(time() + 100)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $parse->validateExpiration();
    }

    public function testDecodePayload()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $time = time() - 10;

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore($time)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'decodePayload');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($time, $result['nbf']);
    }

    public function testDecodeHeader()
    {
        $build = new Build('JWT', new Validate(), new Encode());

        $time = time() - 10;

        $token = $build->setSecret('Hoo1234%&HePPo99')
            ->setNotBefore($time)
            ->build();

        $parse = new Parse(
            $token,
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'decodeHeader');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame('JWT', $result['typ']);
    }

    public function testValidateSignature()
    {
        $parse = new Parse(
            new Jwt(Token::create(1, 'foo1234He$$llo56', time() + 300, 'localhost'), 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $this->assertNull($method->invoke($parse));
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Signature is invalid.
     * @expectedExceptionCode 3
     */
    public function testValidateSignatureBadTokenGoodStructure()
    {
        $parse = new Parse(
            new Jwt('hello.hello.hello', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $method->invoke($parse);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Signature is invalid.
     * @expectedExceptionCode 3
     */
    public function testValidateSignatureEmptyToken()
    {
        $parse = new Parse(
            new Jwt('', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $method->invoke($parse);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Signature is invalid.
     * @expectedExceptionCode 3
     */
    public function testValidateSignatureBadTokenStructure()
    {
        $parse = new Parse(
            new Jwt('car', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $method->invoke($parse);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Signature is invalid.
     * @expectedExceptionCode 3
     */
    public function testValidateSignatureInvalidSignature()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tsVs-jHudH5hV3nNZxGDBe3YRPeH871_Cjs-h23jbT', 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'validateSignature');
        $method->setAccessible(true);

        $method->invoke($parse);
    }

    public function testParseRandomTokenNoSecret()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbWVzIiwiaWF0IjoxNTE2MjM5MDIyfQ.BtrZtcOwhxY9BuV0-Eqc7CybKiWqgr6Y5jFVr15zcFk', ''),
            new Validate,
            new Encode()
        );

        $parsed = $parse->validate()
            ->parse();

        $this->assertSame($parsed->getAlgorithm(), "HS256");
        $this->assertSame($parsed->getType(), "JWT");
        $this->assertSame($parsed->getSubject(), "1234567890");
        $this->assertSame($parsed->getPayload()['name'], 'James');
        $this->assertSame($parsed->getIssuedAt(), 1516239022);
    }

    public function testParseRandomTokenInvalidSecret()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJSVzg0LTIwMTkwMTA5IiwibmFtZSI6IlJvYiIsImlhdCI6MTUxNjIzOTAyMn0.JojSqQXc-nsiongo1I33lsd7eJZ9WbMoZn65_LL1U8A', 'hello'),
            new Validate,
            new Encode()
        );

        $parsed = $parse->validate()
            ->parse();

        $this->assertSame($parsed->getAlgorithm(), "HS256");
        $this->assertSame($parsed->getType(), "JWT");
        $this->assertSame($parsed->getJwtId(), "RW84-20190109");
        $this->assertSame($parsed->getPayload()['name'], 'Rob');
        $this->assertSame($parsed->getIssuedAt(), 1516239022);
    }

    public function testParseRandomTokenValidSecret()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio', '123$car*PARK456'),
            new Validate,
            new Encode()
        );

        $parsed = $parse->validate()
            ->parse();

        $this->assertSame($parsed->getAlgorithm(), "HS256");
        $this->assertSame($parsed->getType(), "JWT");
        $this->assertSame($parsed->getAudience(), "https://google.com");
        $this->assertSame($parsed->getPayload()['name'], 'Chris');
        $this->assertSame($parsed->getIssuedAt(), 1516239022);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Expiration claim has expired.
     * @expectedExceptionCode 4
     */
    public function testParseRandomTokenExpirationException()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJleHAiOjE1MTYyMzkwMjJ9.Pzio_7YdNC2NCcBBmVjRlTTgC4RNofEGYWm9ygx41JQ', '123$car*PARK456'),
            new Validate,
            new Encode()
        );

        $parse->validate()
            ->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Expiration claim is not set.
     * @expectedExceptionCode 6
     */
    public function testParseRandomTokenExpirationNotSetException()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio', '123$car*PARK456'),
            new Validate,
            new Encode()
        );

        $parse->validate()
            ->validateExpiration();
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\ValidateException
     * @expectedExceptionMessage Not Before claim is not set.
     * @expectedExceptionCode 7
     */
    public function testParseRandomTokenNotBeforeNotSetException()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dvb2dsZS5jb20iLCJuYW1lIjoiQ2hyaXMiLCJpYXQiOjE1MTYyMzkwMjJ9.dA-VMA__ZkvaLjSui-dOgNi23KLU52Y--_dutVvohio', '123$car*PARK456'),
            new Validate,
            new Encode()
        );

        $parse->validate()
            ->validateNotBefore();
    }
}
