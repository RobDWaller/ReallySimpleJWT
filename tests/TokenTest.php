<?php

namespace Tests;

use ReallySimpleJWT\Token;
use Carbon\Carbon;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    public function testGetToken()
    {
        $token = Token::getToken(
            1,
            '123ABC%tyd*ere1',
            Carbon::now()->addMinutes(5)->toDateTimeString(),
            '127.0.0.1'
        );

        $this->assertNotEmpty($token);
    }

    public function testValidateToken()
    {
        $token = Token::getToken(
            'abdY',
            'Hello&MikeFooBar123',
            Carbon::now()->addMinutes(5)->toDateTimeString(),
            'http://127.0.0.1'
        );

        $this->assertTrue(Token::validate($token, 'Hello&MikeFooBar123'));
    }

    public function testBuilder()
    {
        $this->assertInstanceOf('ReallySimpleJWT\TokenBuilder', Token::builder());
    }

    public function testValidator()
    {
        $this->assertInstanceOf('ReallySimpleJWT\TokenValidator', Token::validator());
    }

    public function testGetPayload()
    {
        $token = Token::getToken(
            'abdY',
            'Hello*JamesFooBar$!3',
            Carbon::now()->addMinutes(5)->toDateTimeString(),
            'http://127.0.0.1'
        );

        $this->assertSame('abdY', json_decode(Token::getPayload($token))->user_id);
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedException Token string has invalid structure, ensure three strings seperated by dots.
     */
    public function testValidateTokenFail()
    {
        Token::validate('World', 'FooBar');
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
     * @expectedException Token string has invalid structure, ensure three strings seperated by dots.
     */
    public function testGetPayloadFail()
    {
        Token::getPayload('Hello');
    }
}
