<?php

namespace Test;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Validate;
use PHPUnit\Framework\TestCase;

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
}
