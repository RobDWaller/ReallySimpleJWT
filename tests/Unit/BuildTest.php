<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Tokens;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHs256;
use ReallySimpleJWT\Secret;
use ReallySimpleJWT\Exception\BuildException;
use ReallySimpleJWT\Jwt;
use ReflectionMethod;

class BuildTest extends TestCase
{
    public function testGetHeader()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createStub(EncodeHs256::class);
        $encode->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn(Tokens::ALGORITHM);

        $build = new Build('JWT', $validator, $secret, $encode);
        $header = $build->getHeader();
        $this->assertSame($header['alg'], Tokens::ALGORITHM);
        $this->assertSame($header['typ'], 'JWT');
    }

    public function testGetPayload()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $build->setPayloadClaim('exp', 123);
        $payload = $build->getPayload();
        $this->assertSame($payload['exp'], 123);
    }

    public function testSetContentType()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setContentType('JWT');
        $this->assertInstanceOf(Build::class, $result);
        $header = $build->getHeader();
        $this->assertSame($header['cty'], 'JWT');
    }

    public function testSetHeaderClaim()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setHeaderClaim('lng', 'en-GB');
        $this->assertInstanceOf(Build::class, $result);
        $header = $build->getHeader();
        $this->assertSame($header['lng'], 'en-GB');
    }

    public function testSetIssuer()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setIssuer('www.thesite.com');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['iss'], 'www.thesite.com');
    }

    public function testSetSubject()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setSubject('admin');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['sub'], 'admin');
    }

    public function testSetAudienceString()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setAudience('www.thesite.com');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['aud'], 'www.thesite.com');
    }

    public function testSetAudienceArray()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $build->setAudience(['www.thesite.com', 'blog.thesite.com', 'payment.thesite.com']);
        $payload = $build->getPayload();
        $this->assertSame($payload['aud'][0], 'www.thesite.com');
        $this->assertSame($payload['aud'][1], 'blog.thesite.com');
        $this->assertSame($payload['aud'][2], 'payment.thesite.com');
    }

    public function testSetAudienceFail()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $this->expectException(BuildException::class);
        $this->expectExceptionMessage('Invalid Audience claim.');
        $this->expectExceptionCode(10);
        $build->setAudience(1);
    }

    public function testSetExpiration()
    {
        $expiration = time() + 3600;

        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with($expiration)
            ->willReturn(true);

        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setExpiration($expiration);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['exp'], $expiration);
    }

    public function testSetExpirationFail()
    {
        $expiration = time() - 3600;

        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with($expiration)
            ->willReturn(false);

        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $this->expectException(BuildException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);
        $build->setExpiration($expiration);
    }

    public function testSetNotBefore()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $nbf = time();
        $result = $build->setNotBefore($nbf);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['nbf'], $nbf);
    }

    public function testSetIssuedAt()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $iat = time();
        $result = $build->setIssuedAt($iat);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['iat'], $iat);
    }

    public function testSetJwtId()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setJwtId('123');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['jti'], '123');
    }

    public function testSetPayloadClaim()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createMock(Secret::class);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setPayloadClaim('uid', 4);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['uid'], 4);
    }

    public function testSetSecret()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createStub(Secret::class);
        $secret->expects($this->once())
            ->method('validate')
            ->with('ABC!123*def')
            ->willReturn(true);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setSecret('ABC!123*def');
        $this->assertInstanceOf(Build::class, $result);
    }

    public function testSetSecretFail()
    {
        $validator = $this->createMock(Validator::class);
        $secret = $this->createStub(Secret::class);
        $secret->expects($this->once())
            ->method('validate')
            ->with('secret')
            ->willReturn(false);
        $encode = $this->createMock(EncodeHs256::class);

        $build = new Build('JWT', $validator, $secret, $encode);
        $this->expectException(BuildException::class);
        $this->expectExceptionMessage('Invalid secret.');
        $this->expectExceptionCode(9);
        $build->setSecret('secret');
    }

    public function testBuild()
    {
        $validator = $this->createMock(Validator::class);

        $secret = $this->createStub(Secret::class);
        $secret->expects($this->exactly(2))
            ->method('validate')
            ->with(Tokens::SECRET)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHs256::class);
        $encode->expects($this->exactly(2))
            ->method('getAlgorithm')
            ->willReturn(Tokens::ALGORITHM);

        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, Tokens::SECRET)
            ->willReturn(Tokens::SIGNATURE);

        $encode->expects($this->exactly(2))
            ->method('encode')
            ->withConsecutive([Tokens::DECODED_HEADER], [Tokens::DECODED_PAYLOAD])
            ->willReturn(Tokens::HEADER, Tokens::PAYLOAD);

        $build = new Build('JWT', $validator, $secret, $encode);
        $result = $build->setSecret(Tokens::SECRET)
            ->setPayloadClaim('sub', Tokens::DECODED_PAYLOAD['sub'])
            ->setPayloadClaim('name', Tokens::DECODED_PAYLOAD['name'])
            ->setPayloadClaim('iat', Tokens::DECODED_PAYLOAD['iat'])
            ->setPayloadClaim('exp', Tokens::DECODED_PAYLOAD['exp'])
            ->setPayloadClaim('nbf', Tokens::DECODED_PAYLOAD['nbf'])
            ->setPayloadClaim('aud', Tokens::DECODED_PAYLOAD['aud'])
            ->build();

        $this->assertInstanceOf(Jwt::class, $result);
    }
}
