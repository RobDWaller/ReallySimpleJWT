<?php

namespace Tests\Integration;

use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Interfaces\Encode;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Decode;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Exception\BuildException;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Exception\ParseException;
//use ReallySimpleJWT\Interfaces\Decode;
use ReallySimpleJWT\Helper\JsonEncoder;
use PHPUnit\Framework\TestCase;

class BuildParseTest extends TestCase
{
    private const TOKEN_TYPE = 'JWT';

    public function testBuildAndParse(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', 'Hello World')
            ->setSecret('123abcDEF!$£%456')
            ->setIssuer('localhost')
            ->setSubject('users')
            ->setAudience('https://google.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setJwtId('ABC123')
            ->setPayloadClaim('uid', 2)
            ->build();

        $parse = new Parse($token, new Decode());
        $parsed = $parse->parse();

        $this->assertSame($token->getToken(), $parsed->getJwt()->getToken());
        $this->assertSame($token->getSecret(), $parsed->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getType());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getContentType());
        $this->assertSame('Hello World', $parsed->getHeader()['info']);
        $this->assertSame('localhost', $parsed->getIssuer());
        $this->assertSame('users', $parsed->getSubject());
        $this->assertSame('https://google.com', $parsed->getAudience());
        $this->assertSame($expiration, $parsed->getExpiration());
        $this->assertSame($notBefore, $parsed->getNotBefore());
        $this->assertSame($issuedAt, $parsed->getIssuedAt());
        $this->assertSame('ABC123', $parsed->getJwtId());
        $this->assertSame(2, $parsed->getPayload()['uid']);
        $this->assertSame(explode('.', $token->getToken())[2], $parsed->getSignature());
    }

    public function testMultipleTokens(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 11;
        $notBefore = time() - 13;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setSecret('456yuTu#!3456')
            ->setAudience('https://amazon.com')
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setIssuer('mysite.com')
            ->setSubject('admins')
            ->setJwtId('TYHUIP')
            ->setPayloadClaim('uid', 5)
            ->setHeaderClaim('info', 'foo bar')
            ->build();

        $build1 = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;
        $issuedAt1 = time() + 10;

        $token1 = $build1->setContentType('JWE')
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxHgEF!**217')
            ->setSubject('admins')
            ->setIssuer('facebook.com')
            ->setAudience(['https://maps.google.com', 'https://youtube.co.uk'])
            ->setExpiration($expiration1)
            ->setIssuedAt($issuedAt1)
            ->setNotBefore($notBefore1)
            ->setJwtId('456jkl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Decode());

        $parsed = $parse->parse();

        $this->assertSame($token->getToken(), $parsed->getJwt()->getToken());
        $this->assertSame($token->getSecret(), $parsed->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getType());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getContentType());
        $this->assertSame($expiration, $parsed->getExpiration());
        $this->assertSame($notBefore, $parsed->getNotBefore());
        $this->assertSame($issuedAt, $parsed->getIssuedAt());
        $this->assertSame('foo bar', $parsed->getHeader()['info']);
        $this->assertSame('mysite.com', $parsed->getIssuer());
        $this->assertSame('admins', $parsed->getSubject());
        $this->assertSame('https://amazon.com', $parsed->getAudience());
        $this->assertSame('TYHUIP', $parsed->getJwtId());
        $this->assertSame(5, $parsed->getPayload()['uid']);
        $this->assertSame(explode('.', $token->getToken())[2], $parsed->getSignature());

        $parse1 = new Parse($token1, new Decode());

        $parsed1 = $parse1->parse();

        $this->assertSame($token1->getToken(), $parsed1->getJwt()->getToken());
        $this->assertSame($token1->getSecret(), $parsed1->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed1->getType());
        $this->assertSame('JWE', $parsed1->getContentType());
        $this->assertSame('FooBar', $parsed1->getHeader()['claim']);
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame('facebook.com', $parsed1->getIssuer());
        $this->assertSame('admins', $parsed1->getSubject());
        $this->assertSame('https://maps.google.com', $parsed1->getAudience()[0]);
        $this->assertSame('https://youtube.co.uk', $parsed1->getAudience()[1]);
        $this->assertSame($expiration1, $parsed1->getExpiration());
        $this->assertSame($notBefore1, $parsed1->getNotBefore());
        $this->assertSame($issuedAt1, $parsed1->getIssuedAt());
        $this->assertSame('456jkl', $parsed1->getJwtId());
        $this->assertSame(5, $parsed1->getPayload()['user_id']);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame(explode('.', $token1->getToken())[2], $parsed1->getSignature());
    }

    public function testMultipleTokensWithReset(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 19;
        $notBefore = time() - 12;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setSecret('55556kiOP!5555')
            ->setHeaderClaim('info', 'carpark')
            ->setIssuer('thesite.com')
            ->setSubject('editors')
            ->setAudience('https://twitter.com')
            ->setJwtId('56UJ')
            ->setPayloadClaim('uid', 65)
            ->setExpiration($expiration)
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->build();

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;
        $issuedAt1 = time() + 10;

        $token1 = $build->reset()
            ->setJwtId('456HGF')
            ->setHeaderClaim('claim', 'FooBar')
            ->setContentType('JWE')
            ->setSecret('456zxcYUT!$*0921')
            ->setIssuer('instagram.com')
            ->setSubject('admins')
            ->setAudience(['https://apple.com', 'https://duckduckgo.com'])
            ->setExpiration($expiration1)
            ->setIssuedAt($issuedAt1)
            ->setNotBefore($notBefore1)
            ->setPayloadClaim('user_id', 711)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Decode());

        $parsed = $parse->parse();

        $this->assertSame(self::TOKEN_TYPE, $parsed->getType());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getContentType());
        $this->assertSame($token->getToken(), $parsed->getJwt()->getToken());
        $this->assertSame($token->getSecret(), $parsed->getJwt()->getSecret());
        $this->assertSame('carpark', $parsed->getHeader()['info']);
        $this->assertSame('thesite.com', $parsed->getIssuer());
        $this->assertSame('editors', $parsed->getSubject());
        $this->assertSame('https://twitter.com', $parsed->getAudience());
        $this->assertSame($notBefore, $parsed->getNotBefore());
        $this->assertSame($expiration, $parsed->getExpiration());
        $this->assertSame($issuedAt, $parsed->getIssuedAt());
        $this->assertSame('56UJ', $parsed->getJwtId());
        $this->assertSame(explode('.', $token->getToken())[2], $parsed->getSignature());
        $this->assertSame(65, $parsed->getPayload()['uid']);

        $parse1 = new Parse($token1, new Decode());

        $parsed1 = $parse1->parse();

        $this->assertSame($token1->getSecret(), $parsed1->getJwt()->getSecret());
        $this->assertSame($token1->getToken(), $parsed1->getJwt()->getToken());
        $this->assertSame('JWE', $parsed1->getContentType());
        $this->assertSame(self::TOKEN_TYPE, $parsed1->getType());
        $this->assertSame('FooBar', $parsed1->getHeader()['claim']);
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame('instagram.com', $parsed1->getIssuer());
        $this->assertSame('admins', $parsed1->getSubject());
        $this->assertSame('https://apple.com', $parsed1->getAudience()[0]);
        $this->assertSame('https://duckduckgo.com', $parsed1->getAudience()[1]);
        $this->assertSame('456HGF', $parsed1->getJwtId());
        $this->assertSame(711, $parsed1->getPayload()['user_id']);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame(explode('.', $token1->getToken())[2], $parsed1->getSignature());
        $this->assertSame($expiration1, $parsed1->getExpiration());
        $this->assertSame($notBefore1, $parsed1->getNotBefore());
        $this->assertSame($issuedAt1, $parsed1->getIssuedAt());
    }

    public function testMultipleTokensRemovedFields(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setSecret('AHDJ989%653ads')
            ->setIssuer('twitter.com')
            ->setSubject('managers')
            ->setHeaderClaim('info', 'Star Wars')
            ->setAudience('https://reddit.com')
            ->setExpiration($expiration)
            ->setJwtId('5674')
            ->setNotBefore($notBefore)
            ->setIssuedAt($issuedAt)
            ->setPayloadClaim('uid', 268)
            ->build();

        $build1 = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration1 = time() + 20;
        $issuedAt1 = time() + 10;

        $token1 = $build1->setHeaderClaim('claim', 'FooBar')
            ->setSecret('983zxcDEF!$*8921')
            ->setAudience(['https://imgur.com', 'https://youtube.com'])
            ->setIssuer('whatsapp.com')
            ->setExpiration($expiration1)
            ->setIssuedAt($issuedAt1)
            ->setJwtId('321jkl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Decode());

        $parsed = $parse->parse();

        $this->assertSame('Star Wars', $parsed->getHeader()['info']);
        $this->assertSame('twitter.com', $parsed->getIssuer());
        $this->assertSame('managers', $parsed->getSubject());
        $this->assertSame('https://reddit.com', $parsed->getAudience());
        $this->assertSame($expiration, $parsed->getExpiration());
        $this->assertSame($issuedAt, $parsed->getIssuedAt());
        $this->assertSame($notBefore, $parsed->getNotBefore());
        $this->assertSame('5674', $parsed->getJwtId());
        $this->assertSame(268, $parsed->getPayload()['uid']);
        $this->assertSame(explode('.', $token->getToken())[2], $parsed->getSignature());
        $this->assertSame($token->getToken(), $parsed->getJwt()->getToken());
        $this->assertSame($token->getSecret(), $parsed->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getType());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getContentType());

        $parse1 = new Parse($token1, new Decode());

        $parsed1 = $parse1->parse();

        $this->assertSame($token1->getToken(), $parsed1->getJwt()->getToken());
        $this->assertSame($token1->getSecret(), $parsed1->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed1->getType());
        $this->assertSame('FooBar', $parsed1->getHeader()['claim']);
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame('whatsapp.com', $parsed1->getIssuer());
        $this->assertSame('https://youtube.com', $parsed1->getAudience()[1]);
        $this->assertSame('https://imgur.com', $parsed1->getAudience()[0]);
        $this->assertSame($expiration1, $parsed1->getExpiration());
        $this->assertSame(0, $parsed1->getNotBefore());
        $this->assertSame($issuedAt1, $parsed1->getIssuedAt());
        $this->assertSame('321jkl', $parsed1->getJwtId());
        $this->assertSame(5, $parsed1->getPayload()['user_id']);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame(explode('.', $token1->getToken())[2], $parsed1->getSignature());
        $this->assertSame('', $parsed1->getSubject());
        $this->assertSame('', $parsed1->getContentType());
    }

    public function testMultipleTokensWithResetRemoveFields(): void
    {
        $build = new Build(
            self::TOKEN_TYPE,
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );

        $expiration = time() + 10;
        $notBefore = time() - 10;
        $issuedAt = time();

        $token = $build->setContentType(self::TOKEN_TYPE)
            ->setHeaderClaim('info', 'Yo yo yo.')
            ->setIssuer('https://bing.com')
            ->setSubject('users')
            ->setExpiration($expiration)
            ->setAudience('https://api.imgur.com')
            ->setNotBefore($notBefore)
            ->setSecret('HYjuI9o!ropP')
            ->setIssuedAt($issuedAt)
            ->setJwtId('4567')
            ->setPayloadClaim('uid', 5232)
            ->build();

        $expiration1 = time() + 20;
        $notBefore1 = time() - 20;

        $token1 = $build->reset()
            ->setAudience(['https://keep.google.com', 'https://vimeo.com'])
            ->setHeaderClaim('claim', 'FooBar')
            ->setSecret('456zxcDEF!$*0921')
            ->setSubject('admins')
            ->setExpiration($expiration1)
            ->setContentType('JWE')
            ->setNotBefore($notBefore1)
            ->setJwtId('45I9kl')
            ->setPayloadClaim('user_id', 5)
            ->build();

        $this->assertNotSame($token->getToken(), $token1->getToken());

        $parse = new Parse($token, new Decode());

        $parsed = $parse->parse();

        $this->assertSame('users', $parsed->getSubject());
        $this->assertSame('https://api.imgur.com', $parsed->getAudience());
        $this->assertSame($token->getToken(), $parsed->getJwt()->getToken());
        $this->assertSame($token->getSecret(), $parsed->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getType());
        $this->assertSame(self::TOKEN_TYPE, $parsed->getContentType());
        $this->assertSame($expiration, $parsed->getExpiration());
        $this->assertSame($notBefore, $parsed->getNotBefore());
        $this->assertSame($issuedAt, $parsed->getIssuedAt());
        $this->assertSame('4567', $parsed->getJwtId());
        $this->assertSame(5232, $parsed->getPayload()['uid']);
        $this->assertSame(explode('.', $token->getToken())[2], $parsed->getSignature());
        $this->assertSame('Yo yo yo.', $parsed->getHeader()['info']);
        $this->assertSame('https://bing.com', $parsed->getIssuer());

        $parse1 = new Parse($token1, new Decode());

        $parsed1 = $parse1->parse();

        $this->assertSame('JWE', $parsed1->getContentType());
        $this->assertSame('FooBar', $parsed1->getHeader()['claim']);
        $this->assertSame($token1->getToken(), $parsed1->getJwt()->getToken());
        $this->assertSame($token1->getSecret(), $parsed1->getJwt()->getSecret());
        $this->assertSame(self::TOKEN_TYPE, $parsed1->getType());
        $this->assertArrayNotHasKey('info', $parsed1->getHeader());
        $this->assertSame('', $parsed1->getIssuer());
        $this->assertSame('admins', $parsed1->getSubject());
        $this->assertSame($expiration1, $parsed1->getExpiration());
        $this->assertSame($notBefore1, $parsed1->getNotBefore());
        $this->assertSame('https://keep.google.com', $parsed1->getAudience()[0]);
        $this->assertSame('https://vimeo.com', $parsed1->getAudience()[1]);
        $this->assertSame(0, $parsed1->getIssuedAt());
        $this->assertSame('45I9kl', $parsed1->getJwtId());
        $this->assertSame(5, $parsed1->getPayload()['user_id']);
        $this->assertArrayNotHasKey('uid', $parsed1->getPayload());
        $this->assertSame(explode('.', $token1->getToken())[2], $parsed1->getSignature());
    }
}
