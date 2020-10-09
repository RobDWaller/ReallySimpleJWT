<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * Enable the custom encoding and decoding of JSON Web Tokens.
 *
 * @todo remove decode method and separate into own decode class. 4.0.0 fix.
 */
interface Encoder
{
    /**
     * Get the algorithm used to encode the signature string.
     */
    public function getAlgorithm(): string;
}
