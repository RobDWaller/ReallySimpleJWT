<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Token;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\TokenBuilder;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
use ReallySimpleJWT\Helper\Hmac;
use ReallySimpleJWT\Helper\Signature;
use Carbon\Carbon;
use ReflectionMethod;

class LegacyTest extends TestCase
{
    public function testEncodeMethodLegacy()
    {
        $encode = new Encode();

        $encode1 = $encode->encode('batman');

        $encode2 = TokenEncodeDecode::encode('batman');

        $this->assertSame($encode1, $encode2);
    }

    public function testEncodeMethodLegacyTwo()
    {
        $encode = new Encode();

        $encode1 = $encode->encode('batman123$');

        $encode2 = TokenEncodeDecode::encode('batman123$');

        $this->assertSame($encode1, $encode2);
    }

    public function testEncodeMethodLegacyThree()
    {
        $encode = new Encode();

        $encode1 = $encode->encode('b"a"t:ma!n123$');

        $encode2 = TokenEncodeDecode::encode('b"a"t:ma!n123$');

        $this->assertSame($encode1, $encode2);
    }

    public function testEncodeMethodLegacyFour()
    {
        $encode = new Encode();

        $json1 = json_encode(['foo' => 'bar']);

        $encode1 = $encode->encode(!$json1 ? '' : $json1);

        $encode2 = TokenEncodeDecode::encode(!$json1 ? '' : $json1);

        $this->assertSame($encode1, $encode2);
    }

    public function testLegacySignature()
    {
        $encode = new Encode();

        $signature1 = $encode->signature('header', 'footer', 'secret');

        $signature2 = new Signature('header', 'footer', 'secret', 'sha256');

        $this->assertSame($signature1, $signature2->get());
    }

    public function testLegacySignatureTwo()
    {
        $encode = new Encode();

        $signature1 = $encode->signature('header123123', '1223jhkasdajsdkj', 'asdasd12312!3a');

        $signature2 = new Signature('header123123', '1223jhkasdajsdkj', 'asdasd12312!3a', 'sha256');

        $this->assertSame($signature1, $signature2->get());
    }

    public function testLegacyHash()
    {
        $encode = new Encode();

        $hash1 = $encode->hash('sha256', 'helloWorld', '123ABC');

        $hash2 = Hmac::hash('sha256', 'helloWorld', '123ABC');

        $this->assertSame($hash1, $hash2);
    }

    public function testLegacyBuild()
    {
        $build = new Build('JWT', new Validate, new Encode);

        $time = time() + 200;

        $token1 = $build->setPrivateClaim('user_id', 3)
            ->setSecret('!123$!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration($time)
            ->setPrivateClaim('sub', '')
            ->setPrivateClaim('aud', '')
            ->build();

        $build2 = new TokenBuilder();
        $token2 = $build2->setIssuer('https://google.com')
            ->setExpiration($time)
            ->addPayload(['key' => 'user_id', 'value' => 3])
            ->setSecret('!123$!456htHeLOOl!')
            ->build();

        $this->assertSame($token1->getToken(), $token2);
    }

    public function testLegacyHeader()
    {
        $build = new Build('JWT', new Validate, new Encode);

        $header1 = json_encode($build->getHeader());

        $build2 = new TokenBuilder();

        $header2 = $build2->getHeader();

        $this->assertSame($header1, $header2);
    }

    public function testLegacyPayload()
    {
        $time = time() + 10;

        $build = new Build('JWT', new Validate, new Encode);

        $payload1 = json_encode($build->setPrivateClaim('user_id', 3)
            ->setIssuer('https://google.com')
            ->setExpiration($time)
            ->setPrivateClaim('sub', '')
            ->setPrivateClaim('aud', '')
            ->getPayload());

        $build2 = new TokenBuilder();
        $payload2 = $build2->setIssuer('https://google.com')
            ->setExpiration($time)
            ->addPayload(['key' => 'user_id', 'value' => 3])
            ->getPayload();

        $this->assertSame($payload1, $payload2);
    }
}
