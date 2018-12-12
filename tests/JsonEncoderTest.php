<?php

namespace Tests;

use ReallySimpleJWT\Helper\JsonEncoder;
use PHPUnit\Framework\TestCase;

class JsonEncoderTest extends TestCase
{
    use JsonEncoder;

    public function testJsonEncode()
    {
        $array = ['hello' => 'world'];

        $this->assertSame('{"hello":"world"}', $this->jsonEncode($array));
    }

    public function testJsonDecode()
    {
        $json = '{"hello":"world"}';

        $this->assertSame(['hello' => 'world'], $this->jsonDecode($json));
    }
}
