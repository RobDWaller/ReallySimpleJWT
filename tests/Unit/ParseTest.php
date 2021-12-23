<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Tokens;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Decode;

class ParseTest extends TestCase
{
    public function testParse(): void
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->exactly(3))
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(Decode::class);
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

    public function testGetSignature(): void
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(Decode::class);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertSame($parse->getSignature(), Tokens::SIGNATURE);
    }

    public function testGetSignatureEmpty(): void
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn('abc');

        $decode = $this->createMock(Decode::class);

        $parse = new Parse(
            $jwt,
            $decode
        );

        $this->assertEmpty($parse->getSignature());
    }

    public function testGetDecodedHeader(): void
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(Decode::class);
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

    public function testGetDecodedPayload(): void
    {
        $jwt = $this->createMock(Jwt::class);
        $jwt->expects($this->once())
            ->method('getToken')
            ->willReturn(Tokens::TOKEN);

        $decode = $this->createMock(Decode::class);
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
}
