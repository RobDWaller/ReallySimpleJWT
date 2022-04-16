<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Exception\ParsedException;
use ReallySimpleJWT\Jwt;
use Tests\Fixtures\Tokens;

class ParsedTest extends TestCase
{
    public function testParsedGetJWT(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertInstanceOf(Jwt::class, $parsed->getJwt());
    }

    public function testGetHeaderClaim(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertSame('HS256', $parsed->getHeaderClaim('alg'));
    }

    public function testGetHeaderClaimNotSet(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->expectException(ParsedException::class);
        $this->expectExceptionMessage('The header claim alb is not set.');
        $this->expectExceptionCode(6);
        $parsed->getHeaderClaim('alb');
    }

    public function testGetPayloadClaim(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertSame(1516239022, $parsed->getPayloadClaim('exp'));
    }

    public function testGetPayloadClaimNotSet(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->expectException(ParsedException::class);
        $this->expectExceptionMessage('The payload claim nbt is not set.');
        $this->expectExceptionCode(7);
        $parsed->getPayloadClaim('nbt');
    }

    public function testParsedGetHeader(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertSame('JWT', $parsed->getHeader()['typ']);
    }

    public function testParsedGetPayload(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertSame('mysite.com', $parsed->getPayload()['aud']);
    }

    public function testParsedGetSignature(): void
    {
        $jwt = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $jwt,
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertSame(Tokens::SECRET, $parsed->getSignature());
    }

    public function testGetIssuer(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["iss" => "localhost"],
            'hello'
        );

        $this->assertSame('localhost', $parsed->getIssuer());
    }

    public function testGetSubject(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["sub" => "payments"],
            'hello'
        );

        $this->assertSame('payments', $parsed->getSubject());
    }

    public function testGetAudience(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["aud" => "users"],
            'hello'
        );

        $this->assertSame('users', $parsed->getAudience());
    }

    public function testGetAudienceIsArray(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["aud" => ["users", "admins"]],
            'hello'
        );

        $this->assertSame('users', $parsed->getAudience()[0]);
        $this->assertSame('admins', $parsed->getAudience()[1]);
    }

    public function testGetExpiration(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["exp" => 123456],
            'hello'
        );

        $this->assertSame(123456, $parsed->getExpiration());
    }

    public function testGetNotBefore(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["nbf" => 123456],
            'hello'
        );

        $this->assertSame(123456, $parsed->getNotBefore());
    }

    public function testGetIssuedAt(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["iat" => 123456],
            'hello'
        );

        $this->assertSame(123456, $parsed->getIssuedAt());
    }

    public function testGetJwtId(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["jti" => "he6236Yui"],
            'hello'
        );

        $this->assertSame('he6236Yui', $parsed->getJwtId());
    }

    public function testGetAlgorithm(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT", "alg" => "HS256"],
            ["jti" => "he6236Yui"],
            'hello'
        );

        $this->assertSame('HS256', $parsed->getAlgorithm());
    }

    public function testGetType(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["jti" => "he6236Yui"],
            'hello'
        );

        $this->assertSame('JWT', $parsed->getType());
    }

    public function testGetContentType(): void
    {
        $token = $this->createMock(Jwt::class);

        $parsed = new Parsed(
            $token,
            ["cty" => "nested"],
            ["jti" => "he6236Yui"],
            'hello'
        );

        $this->assertSame('nested', $parsed->getContentType());
    }

    public function testGetExpiresIn(): void
    {
        $token = $this->createMock(Jwt::class);

        $time = time() + 300;

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["exp" => $time],
            'hello'
        );

        $result = $parsed->getExpiresIn();

        $this->assertGreaterThan(298, $result);
        $this->assertLessThan(302, $result);
    }

    public function testGetExpiresInNegative(): void
    {
        $token = $this->createMock(Jwt::class);

        $time = time() - 100;

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["exp" => $time],
            'hello'
        );

        $this->assertSame(0, $parsed->getExpiresIn());
    }

    public function testGetUsableIn(): void
    {
        $token = $this->createMock(Jwt::class);

        $time = time() + 200;

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["nbf" => $time],
            'hello'
        );

        $result = $parsed->getUsableIn();

        $this->assertGreaterThan(198, $result);
        $this->assertLessThan(202, $result);
    }

    public function testGetUsableInNegative(): void
    {
        $token = $this->createMock(Jwt::class);

        $time = time() - 100;

        $parsed = new Parsed(
            $token,
            ["typ" => "JWT"],
            ["nbf" => $time],
            'hello'
        );

        $this->assertSame(0, $parsed->getUsableIn());
    }
}
