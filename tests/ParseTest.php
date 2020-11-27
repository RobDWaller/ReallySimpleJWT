<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Tokens;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Exception\ParseException;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Decoders\DecodeHs256;
use ReallySimpleJWT\Exception\ValidateException;
use ReflectionMethod;

class ParseTest extends TestCase
{
    public function testParse(): void
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->exactly(3))
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->exactly(2))
            ->method('decode')
            ->withConsecutive([Tokens::HEADER], [Tokens::PAYLOAD])
            ->willReturn(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $parsed = $parse->parse();

        $this->assertInstanceOf(Parsed::class, $parsed);
        $this->assertSame('HS256', $parsed->getHeader()['alg']);
        $this->assertSame('Sandra Thompson', $parsed->getPayload()['name']);
    }

    public function testGetSignature()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getSignature(), Tokens::SIGNATURE);
    }

    public function testGetSignatureEmpty()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn('abc');

        $decode = $this->createMock(DecodeHs256::class);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertEmpty($parse->getSignature());
    }

    public function testGetExpiration()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with(Tokens::PAYLOAD)
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getExpiration(), Tokens::DECODED_PAYLOAD['exp']);
    }

    public function testGetExpirationFail()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn('abc.def.hij');

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with('def')
            ->willReturn([]);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->expectException(ParseException::class);
        $this->expectExceptionMessage('Expiration claim is not set.');
        $this->expectExceptionCode(6);
        $parse->getExpiration();
    }

    public function testGetNotBefore()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with(Tokens::PAYLOAD)
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getNotBefore(), Tokens::DECODED_PAYLOAD['nbf']);
    }

    public function testGetNotBeforeFail()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn('abc.def.hij');

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with('def')
            ->willReturn([]);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->expectException(ParseException::class);
        $this->expectExceptionMessage('Not Before claim is not set.');
        $this->expectExceptionCode(7);
        $parse->getNotBefore();
    }

    public function testGetAudience()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with(Tokens::PAYLOAD)
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getAudience(), Tokens::DECODED_PAYLOAD['aud']);
    }

    public function testGetAudienceFail()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn('abc.def.hij');

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with('def')
            ->willReturn([]);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->expectException(ParseException::class);
        $this->expectExceptionMessage('Audience claim is not set.');
        $this->expectExceptionCode(11);
        $parse->getAudience();
    }

    public function testGetAlgorithm()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with(Tokens::HEADER)
            ->willReturn(Tokens::DECODED_HEADER);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getAlgorithm(), Tokens::DECODED_HEADER['alg']);
    }

    public function testGetAlgorithmFail()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn('abc.def.hij');

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with('abc')
            ->willReturn([]);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->expectException(ParseException::class);
        $this->expectExceptionMessage('Algorithm claim is not set.');
        $this->expectExceptionCode(13);
        $parse->getAlgorithm();
    }

    public function testGetDecodedHeader()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with(Tokens::HEADER)
            ->willReturn(Tokens::DECODED_HEADER);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getDecodedHeader(), Tokens::DECODED_HEADER);
    }

    public function testGetDecodedPayload()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);
        $decode->expects($this->once())
            ->method('decode')
            ->with(Tokens::PAYLOAD)
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getDecodedPayload(), Tokens::DECODED_PAYLOAD);
    }

    public function testGetToken()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(DecodeHs256::class);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getToken(), Tokens::TOKEN);
    }

    public function testGetSecret()
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getSecret')
            ->willReturn(Tokens::SECRET);

        $decode = $this->createMock(DecodeHs256::class);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getSecret(), Tokens::SECRET);
    }
}
