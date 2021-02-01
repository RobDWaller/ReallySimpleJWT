<?php

namespace Tests\Integration;

use ReallySimpleJWT\Token;
use ReallySimpleJWT\Exception\BuildException;
use ReallySimpleJWT\Exception\TokensException;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    public function testCreateBadSignature(): void
    {
        $this->expectException(BuildException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);

        Token::create(
            5,
            '123',
            time() + 20,
            'localhost'
        );
    }

    public function testCreateBadExpiration(): void
    {
        $this->expectException(BuildException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);

        Token::create(
            5,
            'Hello!123GoodBye',
            time() - 20,
            'localhost'
        );
    }

    public function testCustomPayloadBadArray(): void
    {
        $this->expectException(TokensException::class);
        $this->expectExceptionMessage('Invalid payload claim.');
        $this->expectExceptionCode(8);

        Token::customPayload([
            time(),
            1,
            time() + 10,
            'localhost'
        ], 'Hello&MikeFooBar123');
    }

    public function testCreateValidate(): void
    {
        $token = Token::create(
            3,
            'I*Luv123You456',
            time() + 300,
            'localhost'
        );

        $valid = Token::validate($token, 'I*Luv123You456');

        $this->assertTrue($valid);
    }

    public function testValidateFalse(): void
    {
        $token = Token::create(
            3,
            'I*Luv123You456',
            time() + 300,
            'localhost'
        );

        $valid = Token::validate($token, 'I*H8123You456');

        $this->assertFalse($valid);
    }

    public function testValidateCustomPayload(): void
    {
        $token = Token::customPayload([
            'iat' => time(),
            'uid' => 1,
            'exp' => time() + 10,
            'iss' => 'localhost'
        ], 'Hello&MikeFooBar123');

        $valid = Token::validate($token, 'Hello&MikeFooBar123');

        $this->assertTrue($valid);
    }

    public function testCreateGetPayload(): void
    {
        $expiration = time() + 50;

        $token = Token::create(
            'LW345',
            'The^Secret123456',
            $expiration,
            'localhost'
        );

        $payload = Token::getPayload($token, 'The^Secret123456');

        $this->assertContains('LW345', $payload);
        $this->assertContains($expiration, $payload);
        $this->assertContains('localhost', $payload);
    }

    public function testCustomPayloadGetPayload(): void
    {
        $expiration = time() + 50;

        $token = Token::customPayload(
            [
                'id' => 4576,
                'exp' => $expiration,
                'dev' => true
            ],
            'Password$765890',
        );

        $payload = Token::getPayload($token, 'Password$765890');

        $this->assertSame(
            [
                'id' => 4576,
                'exp' => $expiration,
                'dev' => true
            ],
            $payload
        );
    }

    public function testCreateGetHeader(): void
    {
        $token = Token::create(
            876,
            '83$gfT^%hu7821',
            time() + 20,
            'localhost'
        );

        $header = Token::getHeader($token, '83$gfT^%hu7821');

        $this->assertSame(
            [
                'alg' => 'HS256',
                'typ' => 'JWT'
            ],
            $header
        );
    }

    public function testValidateExpiration(): void
    {
        $token = Token::create(
            1236427,
            'Expiration*1234',
            time() + 20,
            'localhost'
        );

        $valid = Token::validateExpiration($token, 'Expiration*1234');

        $this->assertTrue($valid);
    }

    public function testValidateExpirationFalse(): void
    {
        $token = Token::customPayload([
            'org_id' => 123,
            'exp' => time() - 50,
            'iss' => 'localhost'
        ], 'Expired@12300');

        $valid = Token::validateExpiration($token, 'Expired@12300');

        $this->assertFalse($valid);
    }

    public function testValidateExpirationNotExists(): void
    {
        $token = Token::customPayload([
            'uid' => 88,
            'iss' => 'localhost'
        ], 'No*812@Expiration');

        $valid = Token::validateExpiration($token, 'No*812@Expiration');

        $this->assertFalse($valid);
    }

    public function testValidateNotBefore(): void
    {
        $token = Token::customPayload([
            'user_id' => 'FB456',
            'nbf' => time() - 10,
            'iss' => 'localhost'
        ], 'Not*123$Before');

        $valid = Token::validateNotBefore($token, 'Not*123$Before');

        $this->assertTrue($valid);
    }

    public function testValidateNotBeforeFalse(): void
    {
        $token = Token::customPayload([
            'uid' => 56,
            'nbf' => time() + 10,
            'iss' => 'localhost'
        ], 'Not*123$Before');

        $valid = Token::validateNotBefore($token, 'Not*123$Before');

        $this->assertFalse($valid);
    }

    public function testValidateNotBeforeDoesNotExist(): void
    {
        $token = Token::create(
            432,
            'No*Before123!67',
            time() + 20,
            'localhost'
        );

        $valid = Token::validateNotBefore($token, 'No*Before123!67');

        $this->assertFalse($valid);
    }
}
