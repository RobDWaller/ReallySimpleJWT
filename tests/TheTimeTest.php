<?php

namespace Tests;

use ReallySimpleJWT\Helper\TheTime;
use PHPUnit\Framework\TestCase;

class TheTimeTest extends TestCase
{
    use TheTime;

    public function testGetTheTime()
    {
        $this->assertSame(time(), $this->getTheTime());
    }
}
