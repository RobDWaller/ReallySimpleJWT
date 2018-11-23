<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;

class Parse
{
    private $jwt;

    private $validate;

    public function __construct(Jwt $jwt, Validate $validate)
    {
        $this->jwt = $jwt;

        $this->validate = $validate;
    }

    public function parse(): Parsed
    {
        return new Parsed();
    }
}
