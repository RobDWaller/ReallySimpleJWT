<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
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
        $parse = new Parse(new JWT('Hello', 'secret'), new Validate());

        $this->assertInstanceOf(Parse::class, $parse);
    }

    public function testParseParse()
    {
        $parse = new Parse(
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'), 'foo1234He$$llo56'),
            new Validate
        );

        $this->assertInstanceOf(Parsed::class, $parse->parse());
    }

    public function testParseIssuer()
    {
        $parse = new Parse(
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'foo1234He$$llo56'),
            new Validate
        );

        $result = $parse->parse();

        $this->assertSame('localhost', $result->getPayload()->iss);
    }

    public function testParseSplitToken()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'foo1234He$$llo56'),
            new Validate
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
        $parse = new Parse(
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'foo1234He$$llo56'),
            new Validate
        );

        $method = new ReflectionMethod(Parse::class, 'getPayload');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame('localhost', $result->iss);
    }

    public function testParseGetHeader()
    {
        $parse = new Parse(
            new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXRSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.--dv9fqzYnGdaXstbHDgg5t8ddLZW-YthIOMlNxj__s', 'foo1234He$$llo56'),
            new Validate
        );

        $method = new ReflectionMethod(Parse::class, 'getHeader');
        $method->setAccessible(true);

        $result = $method->invoke($parse);

        $this->assertSame('JWE', $result->typ);
    }

    public function testParseValidate()
    {
        $parse = new Parse(
            new Jwt(Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), 'localhost'), 'foo1234He$$llo56'),
            new Validate
        );

        $method = new ReflectionMethod(Parse::class, 'validate');
        $method->setAccessible(true);

        $this->assertSame(Null, $method->invoke($parse));
    }
}
