<?php namespace ReallySimpleJWT;

/**
 * Abstract Token class that contains some global features for the Token Builder
 * class and the Token Validator class
 */
abstract class TokenAbstract
{
    /**
     * The hash type for the signature hashing
     *
     * @var string
     */
    private $hash = 'sha256';

    /**
     * The JWT hash algorithm type for the Token Header
     *
     * @var string
     */
    private $algorithm = 'HS256';

    /**
     * Return the hash type for the signature hashing
     *
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Return the JWT hash algorithm type for the Token header
     *
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }
}
