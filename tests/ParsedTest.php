<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;

class ParsedTest extends TestCase
{
    public function testParsed()
    {
        $parsed = new Parsed();

        $this->assertInstanceOf(Parsed::class, $parsed);
    }
}
