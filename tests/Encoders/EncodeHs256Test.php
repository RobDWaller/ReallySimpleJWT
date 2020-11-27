<?php

namespace Tests\Encoders;

use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Tokens;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHs256;
use ReallySimpleJWT\Token;
use ReflectionMethod;

class EncodeHs256Test extends TestCase
{
    public function testEncode()
    {
        $encode = new EncodeHs256();

        $this->assertSame(Tokens::HEADER, $encode->encode(Tokens::DECODED_HEADER));
        $this->assertSame(Tokens::PAYLOAD, $encode->encode(Tokens::DECODED_PAYLOAD));
    }

    public function testSignature()
    {
        $encode = new EncodeHs256();

        $signature = $encode->signature(
            Tokens::DECODED_HEADER,
            Tokens::DECODED_PAYLOAD,
            Tokens::SECRET
        );

        $this->assertSame(Tokens::SIGNATURE, $signature);
    }

    public function testUrlEncode(): void
    {
        $encode = new EncodeHs256();

        $method = new ReflectionMethod(EncodeHs256::class, 'urlEncode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, ['!"£$%^&*()1235_-+={POp}[]:;@abE~#,><.?/|\¬']);

        $this->assertSame('ISLCoyQlXiYqKCkxMjM1Xy0rPXtQT3B9W106O0BhYkV-Iyw-PC4_L3xcwqw', $result);
    }

    public function testUrlEncodeIsBase64Url(): void
    {
        $encode = new EncodeHs256();

        $method = new ReflectionMethod(EncodeHs256::class, 'urlEncode');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, ['crayon+/=']);

        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9\-\_\=]+$/', $result);
    }

    public function testHash(): void
    {
        $encode = new EncodeHs256();

        $method = new ReflectionMethod(EncodeHs256::class, 'hash');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, [ 'sha256', 'hello', '123']);

        $this->assertNotSame('hello', $result);
    }

    public function testGetAlgorithm(): void
    {
        $encode = new EncodeHs256();

        $this->assertSame('HS256', $encode->getAlgorithm());
    }

    public function testGetHash(): void
    {
        $encode = new EncodeHs256();

        $method = new ReflectionMethod(EncodeHs256::class, 'getHashAlgorithm');
        $method->setAccessible(true);

        $result = $method->invoke($encode);

        $this->assertSame('sha256', $result);
    }
}
