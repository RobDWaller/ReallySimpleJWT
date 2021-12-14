<?php

declare(strict_types=1);

namespace Tests\Unit;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Exception\JwtException;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    public function testGetToken(): void
    {
        $jwt = new Jwt('Hello.World.Hello');

        $this->assertSame('Hello.World.Hello', $jwt->getToken());
    }

    public function testGetTokenWithRealToken(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' .
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $jwt = new Jwt($token);

        $this->assertSame($token, $jwt->getToken());
    }

    public function testGetTokenFail(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage("Token has an invalid structure.");
        $this->expectExceptionCode(1);
        new Jwt('Hello');
    }
}
