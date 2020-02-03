<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * Enable custom validation of JSON Web Token signature secrets. It is
 * advised secrets are as strong as possible to make sure the token
 * is as secure as possible.
 */
interface Secret
{
    public function validate(string $secret): bool;
}
