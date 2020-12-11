<?php

namespace Tests\Unit;

use ReallySimpleJWT\Helper\Errors;
use PHPUnit\Framework\TestCase;

class ErrorsTest extends TestCase
{
    use Errors;

    public function testIsExpirationError(): void
    {
        $this->assertTrue(self::isExpirationError(1));
        $this->assertTrue(self::isExpirationError(2));
        $this->assertTrue(self::isExpirationError(3));
        $this->assertTrue(self::isExpirationError(4));
    }

    public function testIsExpirationErrorFail(): void
    {
        $this->assertFalse(self::isExpirationError(0));
        $this->assertFalse(self::isExpirationError(5));
    }
}
