<?php

namespace Tests;

use ReallySimpleJWT\Jwt;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    public function testJwt()
    {
        $jwt = new Jwt('Hello', 'secret');

        $this->assertInstanceOf(Jwt::class, $jwt);
    }

    public function testgetToken()
    {
        $jwt = new Jwt('Hello', 'secret');

        $this->assertSame('Hello', $jwt->getToken());
    }

    public function testgetTokenWithRealToken()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $jwt = new Jwt($token, 'secret');

        $this->assertSame($token, $jwt->getToken());
    }

    public function testGetSecret()
    {
        $jwt = new Jwt('Hello', 'secret');

        $this->assertSame('secret', $jwt->getSecret());
    }
}
