<?php

namespace ReallySimpleJWT;

use ReallySimpleJWT\TokenAbstract;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Exception\Validate as ValidateException;

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
        if (!$this->validate->secret($secret)) {
            throw new ValidateException('Please set a valid secret. It must be at least twelve characters in length, contain lower and upper case letters, a number and one of the following characters *&!@%^#$.');
        }

        $this->secret = $secret;

        return $this;
    }

    public function setExpiration(int $timestamp): self
    {
        if (!$this->validate->expiration($timestamp)) {
            throw new ValidateException('The expiration timestamp you set has already expired.');
        }

        return $this;
    }
}
