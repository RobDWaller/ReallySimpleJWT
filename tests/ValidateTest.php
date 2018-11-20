<?php

namespace Test;

use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Jwt;
use PHPUnit\Framework\TestCase;

class ValidateTest extends TestCase
{
    public function testValidate()
    {
        $jwt = new Jwt('Hello');

        $validate = new Validate($jwt);

        $this->assertInstanceOf(Validate::class, $validate);
    }
}
