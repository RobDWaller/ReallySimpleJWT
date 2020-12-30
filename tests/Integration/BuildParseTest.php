<?php

namespace Tests\Integration;

use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Interfaces\Encode;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Encoders\EncodeHs256;
use ReallySimpleJWT\Decoders\DecodeHs256;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Exception\BuildException;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Exception\ParseException;
use ReallySimpleJWT\Interfaces\Decode;
use ReallySimpleJWT\Helper\JsonEncoder;
use PHPUnit\Framework\TestCase;

class BuildParseTest extends TestCase
{
    public function testBuildAndParse(): void
    {
        $build = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $parse = new Parse($token, new DecodeHs256());
        $parsed = $parse->parse();

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

    public function testMultipleTokens(): void
    {
        $build = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $build1 = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $parse = new Parse($token, new DecodeHs256());

        $parsed = $parse->parse();

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

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

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

    public function testMultipleTokensWithReset(): void
    {
        $build = $build = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $parse = new Parse($token, new DecodeHs256());

        $parsed = $parse->parse();

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

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

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

    public function testMultipleTokensRemovedFields(): void
    {
        $build = $build = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $build1 = $build = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $parse = new Parse($token, new DecodeHs256());

        $parsed = $parse->parse();

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

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

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

    public function testMultipleTokensWithResetRemoveFields(): void
    {
        $build = $build = new Build(
            'JWT', 
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

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

        $parse = new Parse($token, new DecodeHs256());

        $parsed = $parse->parse();

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

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

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
}
