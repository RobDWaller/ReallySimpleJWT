<?php

declare(strict_types=1);

namespace Tests\Unit;

use ReallySimpleJWT\Token;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Validate;
use Tests\Fixtures\Tokens;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    public function testCreateToken(): void
    {
        $token = Token::create(
            1,
            '123ABC%tyd*ere1',
            time() + 300,
            '127.0.0.1'
        );

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }

    public function testCustomPayload(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() + 10,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }

    public function testValidateToken(): void
    {
        $this->assertTrue(Token::validate(Tokens::TOKEN, Tokens::SECRET));
    }

    public function testValidateBadStructure(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJpYXQiOjE1NjUzNDYyNDcsInVpZCI6MSwiaXNzIjoibG9jYWxob3N0In0';

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateBadSignature(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJpYXQiOjE1NjUzNDYyNDcsInVpZCI6MSwiaXNzIjoibG9jYWxob3N0In0.' .
            'Z1qtnsznCGB8vDaZKb5h9A0swhyD_Vt5DhFPkL43Kq';

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateExpired(): void
    {
        $this->assertFalse(Token::validateExpiration(Tokens::TOKEN));
    }

    public function testValidateNotBefore(): void
    {
        $this->assertTrue(Token::validateNotBefore(Tokens::TOKEN));
    }

    public function testBuilder(): void
    {
        $this->assertInstanceOf(Build::class, Token::builder(Tokens::SECRET_STRONG));
    }

    public function testParser(): void
    {
        $this->assertInstanceOf(Parse::class, Token::parser(Tokens::TOKEN));
    }

    public function testValidator(): void
    {
        $this->assertInstanceOf(Validate::class, Token::validator(Tokens::TOKEN, Tokens::SECRET));
    }

    public function testGetPayload(): void
    {
        $this->assertSame(Tokens::DECODED_PAYLOAD, Token::getPayload(Tokens::TOKEN));
    }

    public function testGetHeader(): void
    {
        $this->assertSame(Tokens::DECODED_HEADER, Token::getHeader(Tokens::TOKEN));
    }

    public function testValidateTokenFail(): void
    {
        $this->assertFalse(Token::validate('World', 'FooBar'));
    }

    public function testBadTokenGetPayloadEmpty(): void
    {
        $this->assertEmpty(Token::getPayload('Hello'));
    }
}
