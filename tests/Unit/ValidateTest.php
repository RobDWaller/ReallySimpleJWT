<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Exception\ValidateException;
use Tests\Fixtures\Tokens;

class ValidateTest extends TestCase
{
    public function testStructureSuccess(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('structure')
            ->with(Tokens::TOKEN)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->structure());
    }

    public function testStructureFail(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getToken')
            ->willReturn('abc');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('structure')
            ->with('abc')
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Token is invalid.');
        $this->expectExceptionCode(1);
        $validate->structure();
    }

    public function testSignatureSuccess(): void
    {
        $parse = $this->createMock(Parse::class);

        $parse->expects($this->once())
            ->method('getDecodedHeader')
            ->willReturn(Tokens::DECODED_HEADER);

        $parse->expects($this->once())
            ->method('getDecodedPayload')
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $parse->expects($this->once())
            ->method('getSecret')
            ->willReturn(Tokens::SECRET);

        $encode = $this->createMock(EncodeHS256::class);
        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, Tokens::SECRET)
            ->willReturn(Tokens::SIGNATURE);

        $parse->expects($this->once())
            ->method('getSignature')
            ->willReturn(Tokens::SIGNATURE);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('signature')
            ->with(Tokens::SIGNATURE, Tokens::SIGNATURE)
            ->willReturn(true);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->signature());
    }

    public function testSignatureFail(): void
    {
        $parse = $this->createMock(Parse::class);

        $parse->expects($this->once())
            ->method('getDecodedHeader')
            ->willReturn(Tokens::DECODED_HEADER);

        $parse->expects($this->once())
            ->method('getDecodedPayload')
            ->willReturn(Tokens::DECODED_PAYLOAD);

        $parse->expects($this->once())
            ->method('getSecret')
            ->willReturn('hello');

        $encode = $this->createMock(EncodeHS256::class);
        $encode->expects($this->once())
            ->method('signature')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, 'hello')
            ->willReturn('mX0_2dzFlPqR0fyh4J3PPmfQYBz9PlqUut5vXgJaSxY');

        $parse->expects($this->once())
            ->method('getSignature')
            ->willReturn(Tokens::SIGNATURE);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('signature')
            ->with('mX0_2dzFlPqR0fyh4J3PPmfQYBz9PlqUut5vXgJaSxY', Tokens::SIGNATURE)
            ->willReturn(false);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);
        $validate->signature();
    }

    public function testValidateExpiration(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getExpiration')
            ->willReturn(1000);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with(1000)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->expiration());
    }

    public function testValidateExpirationFail(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getExpiration')
            ->willReturn(-5);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with(-5)
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);
        $validate->expiration();
    }

    public function testValidateNotBefore(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getNotBefore')
            ->willReturn(-5);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('notBefore')
            ->with(-5)
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->notBefore());
    }

    public function testValidateNotBeforeFail(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getNotBefore')
            ->willReturn(500);

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('notBefore')
            ->with(500)
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim has not elapsed.');
        $this->expectExceptionCode(5);
        $validate->notBefore();
    }

    public function testValidateAudience(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAudience')
            ->willReturn('site.com');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('audience')
            ->with('site.com', 'site.com')
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->audience('site.com'));
    }

    public function testValidateAudienceFail(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAudience')
            ->willReturn('other.site.com');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('audience')
            ->with('other.site.com', 'site.com')
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Audience claim does not contain provided StringOrURI.');
        $this->expectExceptionCode(2);
        $validate->audience('site.com');
    }

    public function testValidateAlgorithm(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('HS256');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('HS256', ['HS256'])
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->algorithm(['HS256']));
    }

    public function testValidateAlgorithmFail(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('RS256');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('RS256', [])
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim is not valid.');
        $this->expectExceptionCode(12);
        $validate->algorithm([]);
    }

    public function testValidateAlgorithmNotNone(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('HS256');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('hs256', ['none'])
            ->willReturn(false);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->assertInstanceOf(Validate::class, $validate->algorithmNotNone());
    }

    public function testValidateAlgorithmNotNoneFail(): void
    {
        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('none');

        $validator = $this->createMock(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('none', ['none'])
            ->willReturn(true);

        $encode = $this->createMock(EncodeHS256::class);

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim should not be none.');
        $this->expectExceptionCode(14);
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

        $parse = $this->createMock(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('None');

        $validate = new Validate($parse, $encode, $validator);

        $this->expectException(ValidateException::class);
        $validate->algorithmNotNone();
    }
}
