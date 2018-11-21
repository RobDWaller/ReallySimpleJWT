<?php

namespace Test;

use ReallySimpleJWT\Jwt;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    public function testJwt()
    {
        $jwt = new Jwt('Hello', 'secret');

        $this->assertInstanceOf(Jwt::class, $jwt);
    }

    public function testGetJwt()
    {
        $jwt = new Jwt('Hello', 'secret');

        $this->assertSame('Hello', $jwt->getJwt());
    }

    public function testGetJwtWithRealToken()
    {
        $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 'secret');

        $this->assertSame('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', $jwt->getJwt());
    }

    public function testGetSecret()
    {
        $jwt = new Jwt('Hello', 'secret');

        $this->assertSame('secret', $jwt->getSecret());
    }
}
