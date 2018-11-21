<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\TokenAbstract;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;

class Parse extends TokenAbstract
{
    private $jwt;

    private $validate;

    public function __construct(Jwt $jwt, Validate $validate)
    {
        $this->jwt = $jwt;

        $this->validate = $validate;
    }
}
