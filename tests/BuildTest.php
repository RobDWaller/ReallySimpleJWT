<?php

namespace Test;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
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

    public function testGetPayload()
    {
        $build = new Build(new Validate);

        $build->setExpiration(Carbon::now()->addMinutes(5)->getTimestamp());

        $this->assertArrayHasKey('exp', $build->getPayload());
    }
}
