<?php

namespace Tests;

use ReallySimpleJWT\Token;
use ReallySimpleJWT\Exception\ValidateException;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    public function testCreateToken()
    {
        $token = Token::create(
            1,
            '123ABC%tyd*ere1',
            time() + 300,
            '127.0.0.1'
        );

        $this->assertNotEmpty($token);
    }

    public function testValidateToken()
    {
        $token = Token::create(
            'abdY',
            'Hello&MikeFooBar123',
            time() + 300,
            'http://127.0.0.1'
        );

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testCustomPayload()
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() + 10,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertNotEmpty($token);
    }

    public function testValidateCustomPayload()
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() + 10,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadWithoutExpiration()
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadBadStructure()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJpYXQiOjE1NjUzNDYyNDcsInVpZCI6MSwiaXNzIjoibG9jYWxob3N0In0';

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadBadSignature()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            'eyJpYXQiOjE1NjUzNDYyNDcsInVpZCI6MSwiaXNzIjoibG9jYWxob3N0In0.' .
            'Z1qtnsznCGB8vDaZKb5h9A0swhyD_Vt5DhFPkL43Kq';

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadExpired()
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() - 20,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testValidateCustomPayloadWithNotBefore()
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

    public function testValidateCustomPayloadWithBadNotBeforeNoExpiration()
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'nbf' => time() + 20,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $this->assertFalse(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testCustomPayloadBadArray()
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

    public function testBuilder()
    {
        $this->assertInstanceOf('ReallySimpleJWT\Build', Token::builder());
    }

    public function testValidator()
    {
        $this->assertInstanceOf('ReallySimpleJWT\Parse', Token::parser('Hello', '1234'));
    }

    public function testGetPayload()
    {
        $token = Token::create(
            'abdY',
            'Hello*JamesFooBar$!3',
            time() + 300,
            'http://127.0.0.1'
        );

        $this->assertSame('abdY', Token::getPayload($token, 'Hello*JamesFooBar$!3')['user_id']);
    }

    public function testGetHeader()
    {
        $token = Token::create(
            'abdY',
            'Hello*JamesFooBar$!3',
            time() + 300,
            'http://127.0.0.1'
        );

        $this->assertSame('JWT', Token::getHeader($token, 'Hello*JamesFooBar$!3')['typ']);
    }

    public function testValidateTokenFail()
    {
        $this->assertFalse(Token::validate('World', 'FooBar'));
    }

    public function testGetPayloadFail()
    {
        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Token is invalid.');
        $this->expectExceptionCode(1);

        Token::getPayload('Hello', 'CarPark');
    }
}
