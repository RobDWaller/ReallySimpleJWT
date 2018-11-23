<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use Carbon\Carbon;

class ParsedTest extends TestCase
{
    public function testParsed()
    {
        $parsed = new Parsed(
            new Jwt(
                Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'),
                'foo1234He$$llo56'
            ),
            json_decode('{"typ": "JWT"}'),
            json_decode('{"iss": "127.0.0.1"}')
        );

        $this->assertInstanceOf(Parsed::class, $parsed);
    }

    public function testParsedGetJWT()
    {
        $parsed = new Parsed(
            new Jwt(
                Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'),
                'foo1234He$$llo56'
            ),
            json_decode('{"typ": "JWT"}'),
            json_decode('{"iss": "127.0.0.1"}')
        );

        $this->assertInstanceOf(Jwt::class, $parsed->getJwt());
    }

    public function testParsedGetHeader()
    {
        $parsed = new Parsed(
            new Jwt(
                Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'),
                'foo1234He$$llo56'
            ),
            json_decode('{"typ": "JWT"}'),
            json_decode('{"iss": "127.0.0.1"}')
        );

        $this->assertSame('JWT', $parsed->getHeader()->typ);
    }

    public function testParsedGetPayload()
    {
        $parsed = new Parsed(
            new Jwt(
                Token::getToken(1, 'foo1234He$$llo56', Carbon::now()->addMinutes(5)->toDateTimeString(), '127.0.0.1'),
                'foo1234He$$llo56'
            ),
            json_decode('{"typ": "JWT"}'),
            json_decode('{"iss": "127.0.0.1"}')
        );

        $this->assertSame('127.0.0.1', $parsed->getPayload()->iss);
    }
}
