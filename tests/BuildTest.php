<?php

namespace Test;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use PHPUnit\Framework\TestCase;
use Carbon\Carbon;

class BuildTest extends TestCase
{
    public function testBuild()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build);
    }

    public function testBuildSetSecret()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build->setSecret('Hello123$$Abc!!4538'));
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage Please set a valid secret. It must be at least twelve characters in length, contain lower and upper case letters, a number and one of the following characters *&!@%^#$.
     */
    public function testBuildSetSecretInvalid()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build->setSecret('Hello'));
    }

    public function testSetExpiration()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build->setExpiration(Carbon::now()->addMinutes(5)->getTimestamp()));
    }

    /**
     * @expectedException ReallySimpleJWT\Exception\Validate
     * @expectedExceptionMessage The expiration timestamp you set has already expired.
     */
    public function testSetExpirationInvalid()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build->setExpiration(Carbon::now()->subMinutes(5)->getTimestamp()));
    }

    public function testSetExpirationCheckPayload()
    {
        $build = new Build(new Validate);

        $timestamp = Carbon::now()->addMinutes(5)->getTimestamp();

        $build->setExpiration($timestamp);

        $this->assertSame($build->getPayload()['exp'], $timestamp);
    }

    public function testGetPayload()
    {
        $build = new Build(new Validate);

        $build->setExpiration(Carbon::now()->addMinutes(5)->getTimestamp());

        $this->assertArrayHasKey('exp', $build->getPayload());
    }

    public function testSetIssuer()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build->setIssuer('127.0.0.1'));
    }

    public function testSetIssuerCheckPayload()
    {
        $build = new Build(new Validate);

        $build->setIssuer('127.0.0.1');

        $this->assertSame($build->getPayload()['iss'], '127.0.0.1');
    }

    public function testSetPrivateClaim()
    {
        $build = new Build(new Validate);

        $this->assertInstanceOf(Build::class, $build->setPrivateClaim('user_id', 1));
    }

    public function testSetPrivateClaimCheckPayload()
    {
        $build = new Build(new Validate);

        $build->setPrivateClaim('user_id', 1);

        $this->assertSame($build->getPayload()['user_id'], 1);
    }

    public function testBuildMethod()
    {
        $build = new Build(new Validate);

        $token = $build->setSecret('helLLO123$!456ht')
            ->setIssuer('127.0.0.1')
            ->setExpiration(time() + 100)
            ->setPrivateClaim('user_id', 2)
            ->build();

        $this->assertInstanceOf(Jwt::class, $token);
    }

    public function testBuildMethodCheckJwt()
    {
        $build = new Build(new Validate);

        $token = $build->setSecret('!123$!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 200)
            ->setPrivateClaim('user_id', 3)
            ->build();

        $this->assertSame($token->getSecret(), '!123$!456htHeLOOl!');
        $this->assertRegExp('/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/', $token->getToken());
    }

    public function testBuildMethodParse()
    {
        $build = new Build(new Validate);

        $token = $build->setSecret('!123$!456htHeLOOl!')
            ->setIssuer('https://google.com')
            ->setExpiration(time() + 200)
            ->setPrivateClaim('user_id', 3)
            ->build();

        $parse = new Parse($token, new Validate);

        $parsed = $parse->validate()
            ->validateExpiration()
            ->parse();

        $this->assertSames($parsed->getHeader()->user_id, 3);
    }
}
