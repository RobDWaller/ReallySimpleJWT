<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use Carbon\Carbon;
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
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'), 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parsed::class, $parse->parse());
    }

    public function testParseIssuer()
    {
        $parse = new Parse(
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'foo1234He$$llo56'),
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
        $token = new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'foo1234He$$llo56');

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
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'foo1234He$$llo56'),
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validate());
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage The JSON web token has an invalid structure.
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
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage The JSON web token signature is invalid.
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
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage The JSON web token signature is invalid.
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
            new Jwt(Token::getToken(1, 'Hoo1234%&HePPo99', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'Hoo1234%&HePPo99'),
            new Validate,
            new Encode()
        );

        $this->assertInstanceOf(Parse::class, $parse->validateExpiration());
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage The expiration time has elapsed or it was never set, this token is not valid.
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
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage The expiration time has elapsed or it was never set, this token is not valid.
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
        $timestamp = Carbon::now()->addMinutes(5);

        $parse = new Parse(
            new Jwt(Token::getToken(1, 'Hoo1234%&HePPo99', $timestamp->toDateTimeString(), 'localhost'), 'Hoo1234%&HePPo99'),
            new Validate,
            new Encode()
        );

        $method = new ReflectionMethod(Parse::class, 'getExpiration');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame($timestamp->getTimestamp(), $result);
    }
}
