<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Tokens;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Exception\BuildException;
use ReallySimpleJWT\Jwt;

class BuildTest extends TestCase
{
    public function testGetHeader(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);
        $encode->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn(Tokens::ALGORITHM);

        $build = new Build('JWT', $validator, $encode);
        $header = $build->getHeader();
        $this->assertSame($header['alg'], Tokens::ALGORITHM);
        $this->assertSame($header['typ'], 'JWT');
    }

    public function testGetPayload(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $build->setPayloadClaim('exp', 123);
        $payload = $build->getPayload();
        $this->assertSame($payload['exp'], 123);
    }

    public function testSetContentType(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setContentType('JWT');
        $this->assertInstanceOf(Build::class, $result);
        $header = $build->getHeader();
        $this->assertSame($header['cty'], 'JWT');
    }

    public function testSetHeaderClaim(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setHeaderClaim('lng', 'en-GB');
        $this->assertInstanceOf(Build::class, $result);
        $header = $build->getHeader();
        $this->assertSame($header['lng'], 'en-GB');
    }

    public function testSetIssuer(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setIssuer('www.thesite.com');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['iss'], 'www.thesite.com');
    }

    public function testSetSubject(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setSubject('admin');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['sub'], 'admin');
    }

    public function testSetAudienceString(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setAudience('www.thesite.com');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['aud'], 'www.thesite.com');
    }

    public function testSetAudienceArray(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $build->setAudience(['www.thesite.com', 'blog.thesite.com', 'payment.thesite.com']);
        $payload = $build->getPayload();
        $this->assertSame($payload['aud'][0], 'www.thesite.com');
        $this->assertSame($payload['aud'][1], 'blog.thesite.com');
        $this->assertSame($payload['aud'][2], 'payment.thesite.com');
    }

    public function testSetExpiration(): void
    {
        $expiration = time() + 3600;

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with($expiration)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setExpiration($expiration);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['exp'], $expiration);
    }

    public function testSetExpirationFail(): void
    {
        $expiration = time() - 3600;

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with($expiration)
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $this->expectException(BuildException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);
        $build->setExpiration($expiration);
    }

    public function testSetNotBefore(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $nbf = time();
        $result = $build->setNotBefore($nbf);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['nbf'], $nbf);
    }

    public function testSetIssuedAt(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $iat = time();
        $result = $build->setIssuedAt($iat);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['iat'], $iat);
    }

    public function testSetJwtId(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setJwtId('123');
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['jti'], '123');
    }

    public function testSetPayloadClaim(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setPayloadClaim('uid', 4);
        $this->assertInstanceOf(Build::class, $result);
        $payload = $build->getPayload();
        $this->assertSame($payload['uid'], 4);
    }

    public function testBuild(): void
    {
        $validator = $this->createMock(Validator::class);

        $encode = $this->createMock(EncodeHS256::class);
        $encode->expects($this->exactly(2))
            ->method('getAlgorithm')
            ->willReturn(Tokens::ALGORITHM);

        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD)
            ->willReturn(Tokens::SIGNATURE);

        $encode->expects($this->exactly(2))
            ->method('encode')
            ->withConsecutive([Tokens::DECODED_HEADER], [Tokens::DECODED_PAYLOAD])
            ->willReturn(Tokens::HEADER, Tokens::PAYLOAD);

        $build = new Build('JWT', $validator, $encode);
        $result = $build->setPayloadClaim('sub', Tokens::DECODED_PAYLOAD['sub'])
            ->setPayloadClaim('name', Tokens::DECODED_PAYLOAD['name'])
            ->setPayloadClaim('iat', Tokens::DECODED_PAYLOAD['iat'])
            ->setPayloadClaim('exp', Tokens::DECODED_PAYLOAD['exp'])
            ->setPayloadClaim('nbf', Tokens::DECODED_PAYLOAD['nbf'])
            ->setPayloadClaim('aud', Tokens::DECODED_PAYLOAD['aud'])
            ->build();

        $this->assertInstanceOf(Jwt::class, $result);
    }

    public function testReset(): void
    {
        $validator = $this->createMock(Validator::class);
        $encode = $this->createMock(EncodeHS256::class);

        $build = new Build('JWT', $validator, $encode);

        $this->assertInstanceOf(Build::class, $build->reset());
    }
}
