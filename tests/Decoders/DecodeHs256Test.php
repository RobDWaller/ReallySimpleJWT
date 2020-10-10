<?php

namespace Tests\Decoders;

use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Tokens;
use ReallySimpleJWT\Decoders\DecodeHs256;
use ReallySimpleJWT\Token;
use ReflectionMethod;

class DecodeHs256Test extends TestCase
{
    public function testDecode(): void
    {
        $decode = new DecodeHs256();

        $this->assertSame(Tokens::DECODED_HEADER, $decode->decode(Tokens::HEADER));
        $this->assertSame(Tokens::DECODED_PAYLOAD, $decode->decode(Tokens::PAYLOAD));
    }

    public function testUrlDecode(): void
    {
        $decode = new DecodeHs256();

        $method = new ReflectionMethod(DecodeHs256::class, 'urlDecode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($decode, ['SGVsbG8gV29ybGQ=']);

        $this->assertSame('Hello World', $result);
    }

    public function testUrlDecodeFooBar(): void
    {
        $decode = new DecodeHs256();

        $method = new ReflectionMethod(DecodeHs256::class, 'urlDecode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($decode, ['Rm9vIEJhcg==']);

        $this->assertSame('Foo Bar', $result);
    }

    public function testUrlDecodeFooBarTwo(): void
    {
        $decode = new DecodeHs256();

        $method = new ReflectionMethod(DecodeHs256::class, 'urlDecode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($decode, ['Rm9vIEJhcg']);

        $this->assertSame('Foo Bar', $result);
    }

    public function testUrlDecodeSpecialCharacters(): void
    {
        $decode = new DecodeHs256();

        $method = new ReflectionMethod(DecodeHs256::class, 'urlDecode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($decode, ['ISLCoyQlXiYqKClfLSs9e31bXTo7QCd-Iyw-PC4_L3xcwqxg']);

        $this->assertSame('!"£$%^&*()_-+={}[]:;@\'~#,><.?/|\¬`', $result);
    }

    public function testUrlDecodeComplexString(): void
    {
        $decode = new DecodeHs256();

        $method = new ReflectionMethod(DecodeHs256::class, 'urlDecode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($decode, ['ISLCoyQlXiYqKCkxMjM1Xy0rPXtQT3B9W106O0BhYkV-Iyw-PC4_L3xcwqw=']);

        $this->assertSame('!"£$%^&*()1235_-+={POp}[]:;@abE~#,><.?/|\¬', $result);
    }
}