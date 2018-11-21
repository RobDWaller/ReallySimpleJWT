<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use Carbon\Carbon;

class ParseTest extends TestCase
{
    public function testParse()
    {
        $parse = new Parse(new JWT('Hello'), new Validate());

        $this->assertInstanceOf(Parse::class, $parse);
    }
}
