<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Tokens;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Exception\TokensException;
use Tests\Fixtures\Tokens as TokenFixtures;

class TokensTest extends TestCase
{
    public function testBuilder(): void
    {
        $tokens = new Tokens();

        $builder = $tokens->builder();

        $this->assertInstanceOf(Build::class, $builder);
    }

    public function testParser(): void
    {
        $tokens = new Tokens();

        $parser = $tokens->parser('abc.def.ghi', 'secret');

        $this->assertInstanceOf(Parse::class, $parser);
    }

    public function testValidator(): void
    {
        $tokens = new Tokens();

        $validator = $tokens->validator('abc.def.ghi', 'secret');

        $this->assertInstanceOf(Validate::class, $validator);
    }

    public function testCreate(): void
    {
        $tokens = new Tokens();

        $token = $tokens->create('user_id', 123, 'secret123#ABC', time() + 30, 'localhost');

        $this->assertInstanceOf(Jwt::class, $token);
    }

    public function testCustomPayload(): void
    {
        $tokens = new Tokens();

        $payload = [
            'id' => 123,
            'exp' => time() + 20,
            'nbf' => time() - 20
        ];

        $token = $tokens->customPayload($payload, 'secret123#ABC');

        $this->assertInstanceOf(Jwt::class, $token);
    }

    public function testCreateCustomTokenPayloadValidationFail(): void
    {
        $tokens = new Tokens();

        $payload = [
            123 => 123,
            'exp' => time() + 20,
            'nbf' => time() - 20
        ];

        $this->expectException(TokensException::class);
        $this->expectExceptionMessage('Invalid payload claim.');
        $this->expectExceptionCode(8);
        $tokens->customPayload($payload, 'secret123#ABC');
    }

    public function testValidate(): void
    {
        $tokens = new Tokens();

        $this->assertTrue(
            $tokens->validate(TokenFixtures::TOKEN, TokenFixtures::SECRET)
        );
    }

    public function testBasicValidationFail(): void
    {
        $tokens = new Tokens();

        $this->assertFalse(
            $tokens->validate(TokenFixtures::TOKEN, '123')
        );
    }

    public function testValidateExpiration(): void
    {
        $tokens = new Tokens();

        $payload = [
            'id' => 123,
            'exp' => time() + 20,
            'nbf' => time() - 20
        ];

        $token = $tokens->customPayload($payload, 'secret123#ABC');

        $this->assertTrue(
            $tokens->validateExpiration($token->getToken(), 'secret123#ABC')
        );
    }

    public function testValidateExpirationFail(): void
    {
        $tokens = new Tokens();

        $this->assertFalse(
            $tokens->validateExpiration(TokenFixtures::TOKEN, TokenFixtures::SECRET)
        );
    }

    public function testValidateNoExpiration(): void
    {
        $tokens = new Tokens();

        $this->assertFalse(
            $tokens->validateExpiration(TokenFixtures::TOKEN_NO_TIMES, TokenFixtures::SECRET)
        );
    }

    public function testValidateNotBefore(): void
    {
        $tokens = new Tokens();

        $this->assertTrue(
            $tokens->validateNotBefore(TokenFixtures::TOKEN, TokenFixtures::SECRET)
        );
    }

    public function testValidateNotBeforeFail(): void
    {
        $tokens = new Tokens();

        $payload = [
            'id' => 123,
            'exp' => time() + 20,
            'nbf' => time() + 20
        ];

        $token = $tokens->customPayload($payload, 'secret123#ABC');

        $this->assertFalse(
            $tokens->validateNotBefore($token->getToken(), 'secret123#ABC')
        );
    }

    public function testValidateNoNotBefore(): void
    {
        $tokens = new Tokens();

        $this->assertFalse(
            $tokens->validateNotBefore(TokenFixtures::TOKEN_NO_TIMES, TokenFixtures::SECRET)
        );
    }

    public function testGetHeader(): void
    {
        $tokens = new Tokens();

        $header = $tokens->getHeader(TokenFixtures::TOKEN, TokenFixtures::SECRET);

        $this->assertSame($header, TokenFixtures::DECODED_HEADER);
    }

    public function testGetPayload(): void
    {
        $tokens = new Tokens();

        $payload = $tokens->getPayload(TokenFixtures::TOKEN, TokenFixtures::SECRET);

        $this->assertSame($payload, TokenFixtures::DECODED_PAYLOAD);
    }
}
