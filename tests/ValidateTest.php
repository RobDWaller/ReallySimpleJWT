<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Signature;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Exception\ValidateException;
use Tests\Fixtures\Tokens;

class ValidateTest extends TestCase
{
    public function testValidateFail() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getToken')
            ->willReturn('abc');
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('structure')
            ->with('abc')
            ->willReturn(false);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Token is invalid.');
        $this->expectExceptionCode(1);
        $validate->validate();
    }

    public function testValidateSignatureFail() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('structure')
            ->with(Tokens::TOKEN)
            ->willReturn(true);

        $parse->expects($this->once())
            ->method('getDecodedHeader')
            ->willReturn(Tokens::DECODED_HEADER);

        $parse->expects($this->once())
            ->method('getDecodedPayload')
            ->willReturn(Tokens::DECODED_PAYLOAD);
        
        $parse->expects($this->once())
            ->method('getSecret')
            ->willReturn('hello');

        $signature = $this->createStub(Signature::class);
        $signature->expects($this->once())
            ->method('make')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, 'hello')
            ->willReturn('mX0_2dzFlPqR0fyh4J3PPmfQYBz9PlqUut5vXgJaSxY');

        $parse->expects($this->once())
            ->method('getSignature')
            ->willReturn(Tokens::SIGNATURE);

        $validator->expects($this->once())
            ->method('signature')
            ->with('mX0_2dzFlPqR0fyh4J3PPmfQYBz9PlqUut5vXgJaSxY', Tokens::SIGNATURE)
            ->willReturn(false);

        $validate = new Validate($parse, $signature, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Signature is invalid.');
        $this->expectExceptionCode(3);
        $validate->validate();
    }

    public function testValidateSuccess() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('structure')
            ->with(Tokens::TOKEN)
            ->willReturn(true);

        $parse->expects($this->once())
            ->method('getDecodedHeader')
            ->willReturn(Tokens::DECODED_HEADER);

        $parse->expects($this->once())
            ->method('getDecodedPayload')
            ->willReturn(Tokens::DECODED_PAYLOAD);
        
        $parse->expects($this->once())
            ->method('getSecret')
            ->willReturn(Tokens::SECRET);

        $signature = $this->createStub(Signature::class);
        $signature->expects($this->once())
            ->method('make')
            ->with(Tokens::DECODED_HEADER, Tokens::DECODED_PAYLOAD, Tokens::SECRET)
            ->willReturn(Tokens::SIGNATURE);

        $parse->expects($this->once())
            ->method('getSignature')
            ->willReturn(Tokens::SIGNATURE);

        $validator->expects($this->once())
            ->method('signature')
            ->with(Tokens::SIGNATURE, Tokens::SIGNATURE)
            ->willReturn(true);

        $validate = new Validate($parse, $signature, $validator);

        $this->assertInstanceOf(Validate::class, $validate->validate());
    }

    public function testValidateExpiration() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getExpiration')
            ->willReturn(1000);
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with(1000)
            ->willReturn(true);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->assertInstanceOf(Validate::class, $validate->expiration());
    }

    public function testValidateExpirationFail() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getExpiration')
            ->willReturn(-5);
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('expiration')
            ->with(-5)
            ->willReturn(false);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Expiration claim has expired.');
        $this->expectExceptionCode(4);
        $validate->expiration();
    }

    public function testValidateNotBefore() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getNotBefore')
            ->willReturn(-5);
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('notBefore')
            ->with(-5)
            ->willReturn(true);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->assertInstanceOf(Validate::class, $validate->notBefore());
    }

    public function testValidateNotBeforeFail() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getNotBefore')
            ->willReturn(500);
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('notBefore')
            ->with(500)
            ->willReturn(false);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Not Before claim has not elapsed.');
        $this->expectExceptionCode(5);
        $validate->notBefore();
    }

    public function testValidateAudience() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getAudience')
            ->willReturn('site.com');
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('audience')
            ->with('site.com', 'site.com')
            ->willReturn(true);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->assertInstanceOf(Validate::class, $validate->audience('site.com'));
    }

    public function testValidateAudienceFail() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getAudience')
            ->willReturn('other.site.com');
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('audience')
            ->with('other.site.com', 'site.com')
            ->willReturn(false);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Audience claim does not contain provided StringOrURI.');
        $this->expectExceptionCode(2);
        $validate->audience('site.com');
    }

    public function testValidateAlgorithm() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('HS256');
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('HS256', [])
            ->willReturn(true);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->assertInstanceOf(Validate::class, $validate->algorithm());
    }

    public function testValidateAlgorithmFail() 
    {
        $parse = $this->createStub(Parse::class);
        $parse->expects($this->once())
            ->method('getAlgorithm')
            ->willReturn('RS256');
        
        $validator = $this->createStub(Validator::class);
        $validator->expects($this->once())
            ->method('algorithm')
            ->with('RS256', [])
            ->willReturn(false);

        $signature = $this->createMock(Signature::class);

        $validate = new Validate($parse, $signature, $validator);

        $this->expectException(ValidateException::class);
        $this->expectExceptionMessage('Algorithm claim is not valid.');
        $this->expectExceptionCode(12);
        $validate->algorithm([]);
    }
}
