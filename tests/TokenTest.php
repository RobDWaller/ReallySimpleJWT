<?php

namespace Tests;

use ReallySimpleJWT\Token;
use ReallySimpleJWT\Exception\ValidateException;
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
    }

    public function testValidateToken(): void
    {
        $token = Token::create(
            'abdY',
            'Hello&MikeFooBar123',
            time() + 300,
            'http://127.0.0.1'
        );

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
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
    }

    public function testValidateCustomPayload(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() + 10,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadWithoutExpiration(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadBadStructure(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJpYXQiOjE1NjUzNDYyNDcsInVpZCI6MSwiaXNzIjoibG9jYWxob3N0In0';

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadBadSignature(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJpYXQiOjE1NjUzNDYyNDcsInVpZCI6MSwiaXNzIjoibG9jYWxob3N0In0.' .
            'Z1qtnsznCGB8vDaZKb5h9A0swhyD_Vt5DhFPkL43Kq';

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadExpired(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() - 20,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadWithNotBefore(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() + 20,
            'nbf' => time() + 20,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadWithBadNotBeforeNoExpiration(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'nbf' => time() + 20,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testCustomPayloadBadArray(): void
    {
        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Invalid payload claim.');
        $this->expectExceptionCode(8);

        Token::customPayload([
            time(),
            1,
            time() + 10,
            'localhost'
        ], 'Hello&MikeFooBar123');
    }

    public function testBuilder(): void
    {
        $this->assertInstanceOf('ReallySimpleJWT\Build', Token::builder());
    }

    public function testValidator(): void
    {
        $this->assertInstanceOf('ReallySimpleJWT\Parse', Token::parser('Hello', '1234'));
    }

    public function testGetPayload(): void
    {
        $token = Token::create(
            'abdY',
            'Hello*JamesFooBar$!3',
            time() + 300,
            'http://127.0.0.1'
        );

        $this->assertSame('abdY', Token::getPayload($token, 'Hello*JamesFooBar$!3')['user_id']);
    }

    public function testGetHeader(): void
    {
        $token = Token::create(
            'abdY',
            'Hello*JamesFooBar$!3',
            time() + 300,
            'http://127.0.0.1'
        );

        $this->assertSame('JWT', Token::getHeader($token, 'Hello*JamesFooBar$!3')['typ']);
    }

    public function testValidateTokenFail(): void
    {
        $this->assertFalse(Token::validate('World', 'FooBar'));
    }

    public function testGetPayloadFail(): void
    {
        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Token is invalid.');
        $this->expectExceptionCode(1);

        Token::getPayload('Hello', 'CarPark');
    }
}
