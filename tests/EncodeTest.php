<?php

namespace Tests;

use ReallySimpleJWT\Encode;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

class EncodeTest extends TestCase
{
    public function testEncode()
    {
        $encode = new Encode();

        $this->assertInstanceOf(Encode::class, $encode);
    }

    public function testEncodeMethod()
    {
        $encode = new Encode();

        $this->assertRegExp('/^[a-zA-Z0-9\-\_\=]+$/', $encode->encode('world'));
    }

    public function testEncodeMethodIsBase64Url()
    {
        $encode = new Encode();

        $this->assertRegExp('/^[a-zA-Z0-9\-\_\=]+$/', $encode->encode('crayon+/='));
    }

    public function testEncodeMethodHasEncoded()
    {
        $encode = new Encode();

        $result = $encode->encode('world');

        $this->assertNotSame('world', $result);
    }

    public function testEncodeExact()
    {
        $encode = new Encode();

        $result = $encode->encode('!"£$%^&*()1235_-+={POp}[]:;@abE~#,><.?/|\¬');

        $this->assertSame('ISLCoyQlXiYqKCkxMjM1Xy0rPXtQT3B9W106O0BhYkV-Iyw-PC4_L3xcwqw', $result);
    }

    public function testEncodeExactTwo()
    {
        $encode = new Encode();

        $result = $encode->encode('Hello World');

        $this->assertSame('SGVsbG8gV29ybGQ', $result);
    }

    public function testToBase64Url()
    {
        $encode = new Encode();

        $method = new ReflectionMethod(Encode::class, 'toBase64Url');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, ['he=llo+/']);

        $this->assertSame('hello-_', $result);
    }

    public function testToBase64UrlTwo()
    {
        $encode = new Encode();

        $method = new ReflectionMethod(Encode::class, 'toBase64Url');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, ['/Wo==r+/12+/=']);

        $this->assertSame('_Wor-_12-_', $result);
    }

    public function testSignature()
    {
        $encode = new Encode();

        $result = $encode->signature('header', 'footer', 'secret');

        $this->assertRegExp('/^[a-zA-Z0-9\-\_\=]+$/', $result);
    }

    public function testSignatureDoesNotEqualHello()
    {
        $encode = new Encode();

        $result = $encode->signature('header', 'footer', 'secret');

        $this->assertNotSame('Hello', $result);
    }

    public function testHash()
    {
        $encode = new Encode();

        $method = new ReflectionMethod(Encode::class, 'hash');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, [ 'sha256', 'hello', '123']);

        $this->assertNotSame('hello', $result);
    }

    public function testGetAlgorithm()
    {
        $encode = new Encode();

        $this->assertSame('HS256', $encode->getAlgorithm());
    }

    public function testGetHash()
    {
        $encode = new Encode();

        $method = new ReflectionMethod(Encode::class, 'getHashAlgorithm');
        $method->setAccessible(true);

        $result = $method->invoke($encode);

        $this->assertSame('sha256', $result);
    }

    public function testDecode()
    {
        $encode = new Encode();

        $this->assertSame('Hello World', $encode->decode('SGVsbG8gV29ybGQ='));
    }

    public function testDecodeFooBar()
    {
        $encode = new Encode();

        $this->assertSame('Foo Bar', $encode->decode('Rm9vIEJhcg=='));
    }

    public function testDecodeFooBarTwo()
    {
        $encode = new Encode();

        $this->assertSame('Foo Bar', $encode->decode('Rm9vIEJhcg'));
    }

    public function testDecodeSpecialCharacters()
    {
        $encode = new Encode();

        $this->assertSame(
            '!"£$%^&*()_-+={}[]:;@\'~#,><.?/|\¬`',
            $encode->decode('ISLCoyQlXiYqKClfLSs9e31bXTo7QCd-Iyw-PC4_L3xcwqxg')
        );
    }

    public function testDecodeComplexString()
    {
        $encode = new Encode();

        $this->assertSame(
            '!"£$%^&*()1235_-+={POp}[]:;@abE~#,><.?/|\¬',
            $encode->decode('ISLCoyQlXiYqKCkxMjM1Xy0rPXtQT3B9W106O0BhYkV-Iyw-PC4_L3xcwqw=')
        );
    }

    public function testToBase64()
    {
        $encode = new Encode();

        $method = new ReflectionMethod(Encode::class, 'toBase64');
        $method->setAccessible(true);

        $result = $method->invokeArgs($encode, ['QFDvv71ZLO-_ve-_vVF777']);

        $this->assertSame('QFDvv71ZLO+/ve+/vVF777', $result);
    }

    public function testAddPadding()
    {
        $encode = new Encode();

        $method = new ReflectionMethod(Encode::class, 'addPadding');
        $method->setAccessible(true);

        $result = $method->invokeArgs(
            $encode,
            ['QFDvv71ZLO-_ve-_vVF777-92I10XO-_ve-_ve-_vRnvv73vv70r77-9bQQDTzvvv73vv73vv704Ww']
        );

        $this->assertSame(
            'QFDvv71ZLO-_ve-_vVF777-92I10XO-_ve-_ve-_vRnvv73vv70r77-9bQQDTzvvv73vv73vv704Ww==',
            $result
        );
    }
}
