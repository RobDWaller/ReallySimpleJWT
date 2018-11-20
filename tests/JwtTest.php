<?php

namespace Test;

use ReallySimpleJWT\Jwt;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    public function testJwt()
    {
        $jwt = new Jwt('Hello');

        $this->assertInstanceOf(Jwt::class, $jwt);
    }
}
