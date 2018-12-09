<?php

namespace Test;

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
}
