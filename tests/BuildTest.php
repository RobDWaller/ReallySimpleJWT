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
use ReflectionMethod;

class BuildTest extends TestCase
{
    public function testBuild()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->assertInstanceOf(Build::class, $build);
    }

    public function testBuildSetSecret()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->assertInstanceOf(Build::class, $build->setSecret('Hello123$$Abc!!4538'));
    }

    public function testBuildSetSecretInvalid()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $this->assertInstanceOf(Build::class, $build->setSecret('Hello'));
    }

    public function testSetExpiration()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->assertInstanceOf(Build::class, $build->setExpiration(time() + 300));
    }

    public function testSetExpirationInvalid()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);
        $this->assertInstanceOf(Build::class, $build->setExpiration(time() - 300));
    }

    public function testSetExpirationCheckPayload()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $timestamp = time() + 300;

        $build->setExpiration($timestamp);

        $this->assertSame($build->getPayload()['exp'], $timestamp);
    }

    public function testGetPayload()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $build->setExpiration(time() + 300);

        $this->assertArrayHasKey('exp', $build->getPayload());
    }

    public function testSetIssuer()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->assertInstanceOf(Build::class, $build->setIssuer('127.0.0.1'));
    }

    public function testSetIssuerCheckPayload()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $build->setIssuer('127.0.0.1');

        $this->assertSame($build->getPayload()['iss'], '127.0.0.1');
    }

    public function testSetPrivateClaim()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->assertInstanceOf(Build::class, $build->setPayloadClaim('user_id', 1));
    }

    public function testSetPrivateClaimCheckPayload()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $build->setPayloadClaim('user_id', 1);

        $this->assertSame($build->getPayload()['user_id'], 1);
    }

    public function testBuildMethod()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('helLLO123$!456ht')
            ->setIssuer('127.0.0.1')
            ->setExpiration(time() + 100)
            ->setPayloadClaim('user_id', 2)
            ->build();

        $this->assertInstanceOf(Jwt::class, $token);
    }

    public function testBuildMethodCheckJwt()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('!123$!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 200)
            ->setPayloadClaim('user_id', 3)
            ->build();

        $this->assertSame($token->getSecret(), '!123$!456htHeLOOl!');
        $this->assertRegExp('/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/', $token->getToken());
    }

    public function testBuildMethodParse()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token = $build->setSecret('!123$!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 200)
            ->setPayloadClaim('user_id', 3)
            ->build();

        $parse = new Parse($token, new Validate(), new Encode());

        $parsed = $parse->validate()
            ->validateExpiration()
            ->parse();

        $this->assertSame($parsed->getPayload()['user_id'], 3);
    }

    public function testGetHeader()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->getHeader();

        $this->assertSame('JWT', $result['typ']);
        $this->assertSame('HS256', $result['alg']);
    }

    public function testGetHeaderSetContentType()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setContentType('JWT')->getHeader();

        $this->assertSame('JWT', $result['typ']);
        $this->assertSame('HS256', $result['alg']);
        $this->assertSame('JWT', $result['cty']);
    }

    public function testTwoTokenGeneration()
    {
        $build1 = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token1 = $build1->setSecret('$$$pdr432!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 10)
            ->setPayloadClaim('user_id', 5)
            ->build();

        $build2 = new Build('JWT', new Validate(), new Secret(), new Encode());

        $token2 = $build2->setSecret('!123$!9283htHeLOOl!')
            ->setIssuer('https://facebook.com')
            ->setExpiration(time() + 99)
            ->setPayloadClaim('uid', 7)
            ->build();

        $this->assertNotSame($token1->getToken(), $token2->getToken());
    }

    public function testTwoTokenGenerationAndParse()
    {
        $build1 = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time1 = time() + 10;

        $token1 = $build1->setSecret('$$$pdr432!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration($time1)
            ->setPayloadClaim('user_id', 5)
            ->build();

        $build2 = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time2 = time() + 99;

        $token2 = $build2->setSecret('!123$!9283htHeLOOl!')
            ->setIssuer('https://facebook.com')
            ->setExpiration($time2)
            ->setPayloadClaim('uid', 7)
            ->build();

        $parse1 = new Parse($token1, new Validate(), new Encode());

        $parsed1 = $parse1->validate()
            ->validateExpiration()
            ->parse();

        $parse2 = new Parse($token2, new Validate(), new Encode());

        $parsed2 = $parse2->validate()
            ->validateExpiration()
            ->parse();

        $this->assertSame($parsed1->getPayload()['user_id'], 5);
        $this->assertSame($parsed1->getPayload()['exp'], $time1);
        $this->assertSame($parsed1->getPayload()['iss'], 'https://google.com');

        $this->assertSame($parsed2->getPayload()['uid'], 7);
        $this->assertSame($parsed2->getPayload()['exp'], $time2);
        $this->assertSame($parsed2->getPayload()['iss'], 'https://facebook.com');
    }

    public function testResetMethod()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time1 = time() + 10;

        $token1 = $build->setSecret('$$$pdr432!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration($time1)
            ->setPayloadClaim('user_id', 5)
            ->build();

        $time2 = time() + 99;

        $token2 = $build->reset()
            ->setSecret('!123$!9283htHeLOOl!')
            ->setIssuer('https://facebook.com')
            ->setExpiration($time2)
            ->setPayloadClaim('uid', 7)
            ->build();

        $parse1 = new Parse($token1, new Validate(), new Encode());

        $parsed1 = $parse1->validate()
            ->validateExpiration()
            ->parse();

        $parse2 = new Parse($token2, new Validate(), new Encode());

        $parsed2 = $parse2->validate()
            ->validateExpiration()
            ->parse();

        $this->assertSame($parsed1->getPayload()['user_id'], 5);
        $this->assertSame($parsed1->getPayload()['exp'], $time1);
        $this->assertSame($parsed1->getPayload()['iss'], 'https://google.com');

        $this->assertSame($parsed2->getPayload()['uid'], 7);
        $this->assertSame($parsed2->getPayload()['exp'], $time2);
        $this->assertSame($parsed2->getPayload()['iss'], 'https://facebook.com');
    }

    public function testGetSignature()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $build->setSecret('$$$pdr432!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 10)
            ->setPayloadClaim('user_id', 5);

        $method = new ReflectionMethod(Build::class, 'getSignature');
        $method->setAccessible(true);

        $result = $method->invoke($build);

        $this->assertIsString($result);
    }

    public function testGetSignatureOddSpecialCharacters()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $build->setSecret('$£~pdr432!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 10)
            ->setPayloadClaim('user_id', 5);

        $method = new ReflectionMethod(Build::class, 'getSignature');
        $method->setAccessible(true);

        $result = $method->invoke($build);

        $this->assertIsString($result);
    }

    public function testGetSignatureNoSecret()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $build->setIssuer('https://google.com')
            ->setExpiration(time() + 10)
            ->setPayloadClaim('user_id', 5);

        $method = new ReflectionMethod(Build::class, 'getSignature');
        $method->setAccessible(true);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Invalid secret');
        $this->expectExceptionCode(9);
        $result = $method->invoke($build);
    }

    public function testSetHeaderClaim()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setHeaderClaim('enc', 'A128CBC-HS256')
            ->getHeader();

        $this->assertSame($result['enc'], 'A128CBC-HS256');
    }

    public function testSetContentType()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setContentType('JWT')
            ->getHeader();

        $this->assertSame($result['cty'], 'JWT');
    }

    public function testSetSubject()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setSubject('Johnson')
            ->getPayload();

        $this->assertSame($result['sub'], 'Johnson');
    }

    public function testSetAudienceString()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setAudience('Chris')
            ->getPayload();

        $this->assertSame($result['aud'], 'Chris');
    }

    public function testSetAudienceArray()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setAudience(['John', 'Sarah'])
            ->getPayload();

        $this->assertSame($result['aud'][0], 'John');
        $this->assertSame($result['aud'][1], 'Sarah');
    }

    public function testSetAudienceIntFail()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Invalid Audience claim.');
        $this->expectExceptionCode(10);
        $build->setAudience(123);
    }

    public function testSetNotBefore()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time = time();

        $result = $build->setNotBefore($time)
            ->getPayload();

        $this->assertSame($result['nbf'], $time);
    }

    public function testIssuedAt()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $time = time();

        $result = $build->setIssuedAt($time)
            ->getPayload();

        $this->assertSame($result['iat'], $time);
    }

    public function testSetJwtId()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $result = $build->setJwtId('helLo123')
            ->getPayload();

        $this->assertSame($result['jti'], 'helLo123');
    }

    public function testImmediateBuild()
    {
        $build = new Build('JWT', new Validate(), new Secret(), new Encode());

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Invalid secret');
        $this->expectExceptionCode(9);
        $build->build();
    }
}
