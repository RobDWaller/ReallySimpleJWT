<?php namespace ReallySimpleJWT\Helper;

use ReallySimpleJWT\Helper\Hmac;
use ReallySimpleJWT\Helper\TokenEncodeDecode;

/**
 * A simple class that helps generate a JSON Web Token signature
 */
class Signature
{
    /**
     * The JWT Header string
     *
     * @var string
     */
    private $header;

    /**
     * The JWT Payload string
     *
     * @var string
     */
    private $payload;

    /**
     * The secret string / int for the hashing the signature
     *
     * @var string / int
     */
    private $secret;

    /**
     * The JWT hash type string, e.g. sha256
     *
     * @var string
     */
    private $hash;

    /**
     * Constructor for the JWT Signature generation string
     *
     * @param string $header
     * @param string $payload
     * @param string $secret
     * @param string $hash
     */
    public function __construct(string $header, string $payload, string $secret, string $hash)
    {
        $this->header = $header;

        $this->payload = $payload;

        $this->secret = $secret;

        $this->hash = $hash;
    }

    /**
     * Generate and return the JWT Signature
     *
     * @return string
     */
    public function get(): string
    {
        return TokenEncodeDecode::encode(Hmac::hash(
            $this->hash,
            $this->signatureString(),
            $this->secret
        ));
    }

    /**
     * Generate and return the signature string based on the JWT based on the
     * JWT header and payload.
     *
     * @return string
     */
    private function signatureString(): string
    {
        return TokenEncodeDecode::encode($this->header) . '.' . TokenEncodeDecode::encode($this->payload);
    }
}
