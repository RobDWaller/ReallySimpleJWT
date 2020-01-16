<?php

namespace Tests;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Exception\ValidateException;
use PHPUnit\Framework\TestCase;

class EndToEndTest extends TestCase
{
    public function testEndToEnd()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $parse = new Parse($token, new Validate(), new Encode());

        $parsed = $parse->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed->getJwt()->getToken(), $token->getToken());
        $this->assertSame($parsed->getJwt()->getSecret(), $token->getSecret());
        $this->assertSame($parsed->getType(), 'JWT');
        $this->assertSame($parsed->getContentType(), 'JWT');
        $this->assertSame($parsed->getHeader()['info'], 'Hello World');
        $this->assertSame($parsed->getIssuer(), 'localhost');
        $this->assertSame($parsed->getSubject(), 'users');
        $this->assertSame($parsed->getAudience(), 'https://google.com');
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), '123ABC');
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);
    }

    public function testEndToEndMultiToken()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $build1 = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;
        $issuedAt1 = time() + 10;

        $token1 = $build1->setContentType('JWE')
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxcDEF!$*0921')
            ->setIssuer('facebook.com')
            ->setSubject('admins')
            ->setAudience(['https://google.com', 'https://youtube.com'])
            ->setExpiration($expiration1)
            ->setNotBefore($notBefore1)
            ->setIssuedAt($issuedAt1)
            ->setJwtId('456jkl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Validate(), new Encode());

        $parsed = $parse->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed->getJwt()->getToken(), $token->getToken());
        $this->assertSame($parsed->getJwt()->getSecret(), $token->getSecret());
        $this->assertSame($parsed->getType(), 'JWT');
        $this->assertSame($parsed->getContentType(), 'JWT');
        $this->assertSame($parsed->getHeader()['info'], 'Hello World');
        $this->assertSame($parsed->getIssuer(), 'localhost');
        $this->assertSame($parsed->getSubject(), 'users');
        $this->assertSame($parsed->getAudience(), 'https://google.com');
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), '123ABC');
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new Validate(), new Encode());

        $parsed1 = $parse1->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), 'JWT');
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), 'facebook.com');
        $this->assertSame($parsed1->getSubject(), 'admins');
        $this->assertSame($parsed1->getAudience()[0], 'https://google.com');
        $this->assertSame($parsed1->getAudience()[1], 'https://youtube.com');
        $this->assertSame($parsed1->getExpiration(), $expiration1);
        $this->assertSame($parsed1->getNotBefore(), $notBefore1);
        $this->assertSame($parsed1->getIssuedAt(), $issuedAt1);
        $this->assertSame($parsed1->getJwtId(), '456jkl');
        $this->assertSame($parsed1->getPayload()['user_id'], 5);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame($parsed1->getSignature(), explode('.', $token1->getToken())[2]);
    }

    public function testEndToEndMultiTokenWithReset()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;
        $issuedAt1 = time() + 10;

        $token1 = $build->reset()
            ->setContentType('JWE')
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxcDEF!$*0921')
            ->setIssuer('facebook.com')
            ->setSubject('admins')
            ->setAudience(['https://google.com', 'https://youtube.com'])
            ->setExpiration($expiration1)
            ->setNotBefore($notBefore1)
            ->setIssuedAt($issuedAt1)
            ->setJwtId('456jkl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Validate(), new Encode());

        $parsed = $parse->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed->getJwt()->getToken(), $token->getToken());
        $this->assertSame($parsed->getJwt()->getSecret(), $token->getSecret());
        $this->assertSame($parsed->getType(), 'JWT');
        $this->assertSame($parsed->getContentType(), 'JWT');
        $this->assertSame($parsed->getHeader()['info'], 'Hello World');
        $this->assertSame($parsed->getIssuer(), 'localhost');
        $this->assertSame($parsed->getSubject(), 'users');
        $this->assertSame($parsed->getAudience(), 'https://google.com');
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), '123ABC');
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new Validate(), new Encode());

        $parsed1 = $parse1->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), 'JWT');
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), 'facebook.com');
        $this->assertSame($parsed1->getSubject(), 'admins');
        $this->assertSame($parsed1->getAudience()[0], 'https://google.com');
        $this->assertSame($parsed1->getAudience()[1], 'https://youtube.com');
        $this->assertSame($parsed1->getExpiration(), $expiration1);
        $this->assertSame($parsed1->getNotBefore(), $notBefore1);
        $this->assertSame($parsed1->getIssuedAt(), $issuedAt1);
        $this->assertSame($parsed1->getJwtId(), '456jkl');
        $this->assertSame($parsed1->getPayload()['user_id'], 5);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame($parsed1->getSignature(), explode('.', $token1->getToken())[2]);
    }

    public function testEndToEndMultiTokenRemovedFields()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $build1 = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration1 = time() + 20;
        $issuedAt1 = time() + 10;

        $token1 = $build1->setContentType('JWE')
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxcDEF!$*0921')
            ->setIssuer('facebook.com')
            ->setAudience(['https://google.com', 'https://youtube.com'])
            ->setExpiration($expiration1)
            ->setIssuedAt($issuedAt1)
            ->setJwtId('456jkl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Validate(), new Encode());

        $parsed = $parse->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed->getJwt()->getToken(), $token->getToken());
        $this->assertSame($parsed->getJwt()->getSecret(), $token->getSecret());
        $this->assertSame($parsed->getType(), 'JWT');
        $this->assertSame($parsed->getContentType(), 'JWT');
        $this->assertSame($parsed->getHeader()['info'], 'Hello World');
        $this->assertSame($parsed->getIssuer(), 'localhost');
        $this->assertSame($parsed->getSubject(), 'users');
        $this->assertSame($parsed->getAudience(), 'https://google.com');
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), '123ABC');
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new Validate(), new Encode());

        $parsed1 = $parse1->validate()
            ->validateExpiration()
            ->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), 'JWT');
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), 'facebook.com');
        $this->assertSame($parsed1->getSubject(), '');
        $this->assertSame($parsed1->getAudience()[0], 'https://google.com');
        $this->assertSame($parsed1->getAudience()[1], 'https://youtube.com');
        $this->assertSame($parsed1->getExpiration(), $expiration1);
        $this->assertSame($parsed1->getNotBefore(), 0);
        $this->assertSame($parsed1->getIssuedAt(), $issuedAt1);
        $this->assertSame($parsed1->getJwtId(), '456jkl');
        $this->assertSame($parsed1->getPayload()['user_id'], 5);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame($parsed1->getSignature(), explode('.', $token1->getToken())[2]);
    }

    public function testEndToEndMultiTokenWithResetRemoveFields()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;

        $token1 = $build->reset()
            ->setContentType('JWE')
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxcDEF!$*0921')
            ->setSubject('admins')
            ->setAudience(['https://google.com', 'https://youtube.com'])
            ->setExpiration($expiration1)
            ->setNotBefore($notBefore1)
            ->setJwtId('456jkl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Validate(), new Encode());

        $parsed = $parse->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed->getJwt()->getToken(), $token->getToken());
        $this->assertSame($parsed->getJwt()->getSecret(), $token->getSecret());
        $this->assertSame($parsed->getType(), 'JWT');
        $this->assertSame($parsed->getContentType(), 'JWT');
        $this->assertSame($parsed->getHeader()['info'], 'Hello World');
        $this->assertSame($parsed->getIssuer(), 'localhost');
        $this->assertSame($parsed->getSubject(), 'users');
        $this->assertSame($parsed->getAudience(), 'https://google.com');
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), '123ABC');
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new Validate(), new Encode());

        $parsed1 = $parse1->validate()
            ->validateExpiration()
            ->validateNotBefore()
            ->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), 'JWT');
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), '');
        $this->assertSame($parsed1->getSubject(), 'admins');
        $this->assertSame($parsed1->getAudience()[0], 'https://google.com');
        $this->assertSame($parsed1->getAudience()[1], 'https://youtube.com');
        $this->assertSame($parsed1->getExpiration(), $expiration1);
        $this->assertSame($parsed1->getNotBefore(), $notBefore1);
        $this->assertSame($parsed1->getIssuedAt(), 0);
        $this->assertSame($parsed1->getJwtId(), '456jkl');
        $this->assertSame($parsed1->getPayload()['user_id'], 5);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame($parsed1->getSignature(), explode('.', $token1->getToken())[2]);
    }

    public function testEndToEndBadExpiration()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() - 20;
        $notBefore = time() - 10;
        $issuedAt = time();

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration);
    }

    public function testEndToEndBadNotBefore()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $expiration = time() + 20;
        $notBefore = time() + 20;
        $issuedAt = time();

        $token = $build->setContentType('JWT')
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('123ABC')
            ->setPayloadClaim('uid', 2)
            ->build();

        $parse = new Parse($token, new Validate(), new Encode());

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim has not elapsed.');
        $this->expectExceptionCode(5);

        $parsed = $parse->validate()
            ->validateNotBefore();
    }

    public function testEndToEndBadSignature()
    {
        $token = 'eyJjdHkiOiJKV1QiLCJpbmZvIjoiSGVsbG8gV29ybGQiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
        'eyJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJ1c2VycyIsImF1ZCI6Imh0dHBzOi8vZ29vZ2xlLmNvbSIsImV4cCI6MTU0N' .
        'jE4MTA2MiwibmJmIjoxNTQ2MTgxMDYyLCJpYXQiOjE1NDYxODEwNDIsImp0aSI6IjEyM0FCQyIsInVpZCI6M30.' .
        'SGxo3LiVYRBfFL8pX1QM-dQSMBCf93OWpE0ZnCiQiFc';

        $token = new Jwt(
            $token,
            '123abcDEF!$£%456'
        );

        $parse = new Parse($token, new Validate(), new Encode());

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);

        $parsed = $parse->validate();
    }
}
