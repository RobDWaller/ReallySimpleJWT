<?php

namespace ReallySimpleJWT;

use ReallySimpleJWT\TokenAbstract;
use ReallySimpleJWT\Validate;

class Build extends TokenAbstract
{
    private $validate;

    public function __construct(Validate $validate)
    {
        $this->validate = $validate;
    }
}
