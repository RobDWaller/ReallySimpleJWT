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
    private const TOKEN_TYPE = 'JWT';

    private const TOKEN_AUDIENCE = 'https://google.com';

    private const TOKEN_SECRET = '123abcDEF!$£%456';

    private const TOKEN_ISSUER = 'localhost';

    private const TOKEN_INFO = 'Hello World';

    private const TOKEN_SUBJECT = 'users';

    private const TOKEN_JWTID = '123ABC';

    public function testBuildAndParse(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', self::TOKEN_INFO)
            ->setSecret(self::TOKEN_SECRET)
            ->setIssuer(self::TOKEN_ISSUER)
            ->setSubject(self::TOKEN_SUBJECT)
            ->setAudience(self::TOKEN_AUDIENCE)
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId(self::TOKEN_JWTID)
            ->setPayloadClaim('uid', 2)
            ->build();

        $parse = new Parse($token, new DecodeHs256());
        $parsed = $parse->parse();

        $this->assertSame($token->getToken(), $parsed->getJwt()->getToken());
        $this->assertSame($token->getSecret(), $parsed->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getType());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getContentType());
        $this->assertSame(self::TOKEN_INFO, $parsed->getHeader()['info']);
        $this->assertSame(self::TOKEN_ISSUER, $parsed->getIssuer());
        $this->assertSame(self::TOKEN_SUBJECT, $parsed->getSubject());
        $this->assertSame(self::TOKEN_AUDIENCE, $parsed->getAudience());
        $this->assertSame($expiration, $parsed->getExpiration());
        $this->assertSame($notBefore, $parsed->getNotBefore());
        $this->assertSame($issuedAt, $parsed->getIssuedAt());
        $this->assertSame(self::TOKEN_JWTID, $parsed->getJwtId());
        $this->assertSame(2, $parsed->getPayload()['uid']);
        $this->assertSame(explode('.', $token->getToken())[2], $parsed->getSignature());
    }

    public function testMultipleTokens(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', self::TOKEN_INFO)
            ->setSecret(self::TOKEN_SECRET)
            ->setIssuer(self::TOKEN_ISSUER)
            ->setSubject(self::TOKEN_SUBJECT)
            ->setAudience(self::TOKEN_AUDIENCE)
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId(self::TOKEN_JWTID)
            ->setPayloadClaim('uid', 2)
            ->build();

        $build1 = new Build(
            self::TOKEN_TYPE,
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
            ->setAudience([self::TOKEN_AUDIENCE, 'https://youtube.com'])
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
        $this->assertSame($parsed->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getContentType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getHeader()['info'], self::TOKEN_INFO);
        $this->assertSame($parsed->getIssuer(), self::TOKEN_ISSUER);
        $this->assertSame($parsed->getSubject(), self::TOKEN_SUBJECT);
        $this->assertSame($parsed->getAudience(), self::TOKEN_AUDIENCE);
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), self::TOKEN_JWTID);
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), 'facebook.com');
        $this->assertSame($parsed1->getSubject(), 'admins');
        $this->assertSame($parsed1->getAudience()[0], self::TOKEN_AUDIENCE);
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
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', self::TOKEN_INFO)
            ->setSecret(self::TOKEN_SECRET)
            ->setIssuer(self::TOKEN_ISSUER)
            ->setSubject(self::TOKEN_SUBJECT)
            ->setAudience(self::TOKEN_AUDIENCE)
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId(self::TOKEN_JWTID)
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
            ->setAudience([self::TOKEN_AUDIENCE, 'https://youtube.com'])
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
        $this->assertSame($parsed->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getContentType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getHeader()['info'], self::TOKEN_INFO);
        $this->assertSame($parsed->getIssuer(), self::TOKEN_ISSUER);
        $this->assertSame($parsed->getSubject(), self::TOKEN_SUBJECT);
        $this->assertSame($parsed->getAudience(), self::TOKEN_AUDIENCE);
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), self::TOKEN_JWTID);
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), 'facebook.com');
        $this->assertSame($parsed1->getSubject(), 'admins');
        $this->assertSame($parsed1->getAudience()[0], self::TOKEN_AUDIENCE);
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
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', self::TOKEN_INFO)
            ->setSecret(self::TOKEN_SECRET)
            ->setIssuer(self::TOKEN_ISSUER)
            ->setSubject(self::TOKEN_SUBJECT)
            ->setAudience(self::TOKEN_AUDIENCE)
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId(self::TOKEN_JWTID)
            ->setPayloadClaim('uid', 2)
            ->build();

        $build1 = $build = new Build(
            self::TOKEN_TYPE,
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
            ->setAudience([self::TOKEN_AUDIENCE, 'https://youtube.com'])
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
        $this->assertSame($parsed->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getContentType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getHeader()['info'], self::TOKEN_INFO);
        $this->assertSame($parsed->getIssuer(), self::TOKEN_ISSUER);
        $this->assertSame($parsed->getSubject(), self::TOKEN_SUBJECT);
        $this->assertSame($parsed->getAudience(), self::TOKEN_AUDIENCE);
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), self::TOKEN_JWTID);
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), 'facebook.com');
        $this->assertSame($parsed1->getSubject(), '');
        $this->assertSame($parsed1->getAudience()[0], self::TOKEN_AUDIENCE);
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
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', self::TOKEN_INFO)
            ->setSecret(self::TOKEN_SECRET)
            ->setIssuer(self::TOKEN_ISSUER)
            ->setSubject(self::TOKEN_SUBJECT)
            ->setAudience(self::TOKEN_AUDIENCE)
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId(self::TOKEN_JWTID)
            ->setPayloadClaim('uid', 2)
            ->build();

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;

        $token1 = $build->reset()
            ->setContentType('JWE')
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxcDEF!$*0921')
            ->setSubject('admins')
            ->setAudience([self::TOKEN_AUDIENCE, 'https://youtube.com'])
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
        $this->assertSame($parsed->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getContentType(), self::TOKEN_TYPE);
        $this->assertSame($parsed->getHeader()['info'], self::TOKEN_INFO);
        $this->assertSame($parsed->getIssuer(), self::TOKEN_ISSUER);
        $this->assertSame($parsed->getSubject(), self::TOKEN_SUBJECT);
        $this->assertSame($parsed->getAudience(), self::TOKEN_AUDIENCE);
        $this->assertSame($parsed->getExpiration(), $expiration);
        $this->assertSame($parsed->getNotBefore(), $notBefore);
        $this->assertSame($parsed->getIssuedAt(), $issuedAt);
        $this->assertSame($parsed->getJwtId(), self::TOKEN_JWTID);
        $this->assertSame($parsed->getPayload()['uid'], 2);
        $this->assertSame($parsed->getSignature(), explode('.', $token->getToken())[2]);

        $parse1 = new Parse($token1, new DecodeHs256());

        $parsed1 = $parse1->parse();

        $this->assertSame($parsed1->getJwt()->getToken(), $token1->getToken());
        $this->assertSame($parsed1->getJwt()->getSecret(), $token1->getSecret());
        $this->assertSame($parsed1->getType(), self::TOKEN_TYPE);
        $this->assertSame($parsed1->getContentType(), 'JWE');
        $this->assertSame($parsed1->getHeader()['claim'], 'FooBar');
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame($parsed1->getIssuer(), '');
        $this->assertSame($parsed1->getSubject(), 'admins');
        $this->assertSame($parsed1->getAudience()[0], self::TOKEN_AUDIENCE);
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
