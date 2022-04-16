<?php

declare(strict_types=1);

namespace Tests\Integration;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Encoders\EncodeHS256Strong;
use ReallySimpleJWT\Decode;
use PHPUnit\Framework\TestCase;

class BuildValidateTest extends TestCase
{
    public function testBadExpiration(): void
    {
        $build = new Build(
            'JWT',
            new Validator(),
            new EncodeHS256('123abcDEF!$£%456')
        );

        $expiration = time() - 20;

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setPayloadClaim('exp', $expiration)
            ->build();

        $parse = new Parse($token, new Decode());

        $validate = new Validate(
            $parse->parse(),
            new EncodeHS256('123abcDEF!$£%456'),
            new Validator()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);

        $validate->expiration();
    }

    public function testBadNotBefore(): void
    {
        $build = new Build(
            'JWT',
            new Validator(),
            new EncodeHS256Strong('DEF987!$£%456vdg')
        );

        $expiration = time() + 20;
        $notBefore = time() + 20;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $parse = new Parse($token, new Decode());

        $validate = new Validate(
            $parse->parse(),
            new EncodeHS256('DEF987!$£%456vdg'),
            new Validator()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim has not elapsed.');
        $this->expectExceptionCode(5);

        $validate->notBefore();
    }

    public function testBadSignature(): void
    {
        $token = 'eyJjdHkiOiJKV1QiLCJpbmZvIjoiSGVsbG8gV29ybGQiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJ1c2VycyIsImF1ZCI6Imh0dHBzOi8vZ29vZ2xlLmNvbSIsImV4cCI6MTU0N' .
        'jE4MTA2MiwibmJmIjoxNTQ2MTgxMDYyLCJpYXQiOjE1NDYxODEwNDIsImp0aSI6IjEyM0FCQyIsInVpZCI6M30.' .
        'SGxo3LiVYRBfFL8pX1QM-dQSMBCf93OWpE0ZnCiQiFc';

        $jwt = new Jwt($token);

        $parse = new Parse($jwt, new Decode());

        $validate = new Validate(
            $parse->parse(),
            new EncodeHS256('!$£%456hftYuJi2'),
            new Validator()
        );

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $validate->signature();
    }
}
