<?php

namespace ReallySimpleJWT;

use ReallySimpleJWT\TokenAbstract;
use ReallySimpleJWT\Validate;

class Build extends TokenAbstract
{
    private $validate;

    private $secret;

    public function __construct(Validate $validate)
    {
        $this->validate = $validate;
    }

    public function setSecret(string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }
}
