<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use Carbon\Carbon;

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
}
