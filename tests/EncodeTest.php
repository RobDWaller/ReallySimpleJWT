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
}
