<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Exception\ValidateException;
use Tests\Fixtures\Tokens;

class ValidateTest extends TestCase
{
    public function testSignatureSuccess(): void
    {
        $parsed = $this->createMock(Parsed::class);

        $parsed->expects($this->once())
            ->method('getHeader')
            ->willReturn(Tokens::DECODED_HEADER);

        $parsed->expects($this->once())
            ->method('getPayload')
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $encode = $this->createMock(EncodeHS256::class);
        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD)
            ->willReturn(Tokens::SIGNATURE);

        $parsed->expects($this->once())
            ->method('getSignature')
            ->willReturn(Tokens::SIGNATURE);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('signature')
            ->with(Tokens::SIGNATURE, Tokens::SIGNATURE)
            ->willReturn(true);

        $validate = new Validate($parsed, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->signature());
    }

    public function testSignatureFail(): void
    {
        $parsed = $this->createMock(Parsed::class);

        $parsed->expects($this->once())
            ->method('getHeader')
            ->willReturn(Tokens::DECODED_HEADER);

        $parsed->expects($this->once())
            ->method('getPayload')
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $encode = $this->createMock(EncodeHS256::class);
        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD)
            ->willReturn('mX0_2dzFlPqR0fyh4J3PPmfQYBz9PlqUut5vXgJaSxY');

        $parsed->expects($this->once())
            ->method('getSignature')
            ->willReturn(Tokens::SIGNATURE);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('signature')
            ->with('mX0_2dzFlPqR0fyh4J3PPmfQYBz9PlqUut5vXgJaSxY', Tokens::SIGNATURE)
            ->willReturn(false);

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);
        $validate->signature();
    }

    public function testValidateExpiration(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getExpiration')
            ->willReturn(1000);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with(1000)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->expiration());
    }

    public function testValidateExpirationFail(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getExpiration')
            ->willReturn(-5);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with(-5)
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);
        $validate->expiration();
    }

    public function testValidateNotBefore(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getNotBefore')
            ->willReturn(-5);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('notBefore')
            ->with(-5)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->notBefore());
    }

    public function testValidateNotBeforeFail(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getNotBefore')
            ->willReturn(500);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('notBefore')
            ->with(500)
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim has not elapsed.');
        $this->expectExceptionCode(5);
        $validate->notBefore();
    }

    public function testValidateAudience(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAudience')
            ->willReturn('site.com');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('audience')
            ->with('site.com', 'site.com')
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->audience('site.com'));
    }

    public function testValidateAudienceFail(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAudience')
            ->willReturn('other.site.com');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('audience')
            ->with('other.site.com', 'site.com')
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Audience claim does not contain provided StringOrURI.');
        $this->expectExceptionCode(2);
        $validate->audience('site.com');
    }

    public function testValidateAlgorithm(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('HS256');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('HS256', ['HS256'])
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->algorithm(['HS256']));
    }

    public function testValidateAlgorithmFail(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('RS256');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('RS256', [])
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim is not valid.');
        $this->expectExceptionCode(10);
        $validate->algorithm([]);
    }

    public function testValidateAlgorithmNotNone(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('HS256');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('hs256', ['none'])
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->algorithmNotNone());
    }

    public function testValidateAlgorithmNotNoneFail(): void
    {
        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('none');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('none', ['none'])
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim should not be none.');
        $this->expectExceptionCode(11);
        $validate->algorithmNotNone();
    }

    public function testValidateAlgorithmNotNoneCapitalCaseFail(): void
    {
        $encode = $this->createMock(EncodeHS256::class);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('none', ['none'])
            ->willReturn(true);

        $parsed = $this->createMock(Parsed::class);
        $parsed->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('None');

        $validate = new Validate($parsed, $encode, $validator);

        $this->expectException(ValidateException::class);
        $validate->algorithmNotNone();
    }
}
