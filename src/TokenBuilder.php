<?php namespace ReallySimpleJWT;

use ReallySimpleJWT\Exception\TokenBuilderException;
use ReallySimpleJWT\Helper\Signature;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
use ReallySimpleJWT\Helper\DateTime;

/**
 * Class that generates a JSON Web Token, uses HS256 to generate the signature
 *
 * @author Rob Waller <rdwaller1984@gmail.com>
 */
class TokenBuilder extends TokenAbstract
{
    /**
     * Header token type attribute
     *
     * @var string
     */
    private $type = 'JWT';

    /**
     * Secret string or integer for generating JWT Signature
     *
     * @var string / int
     */
    private $secret;

    /**
     * Payload expiration date time string
     *
     * @var Carbon\Carbon
     */
    private $expiration;

    /**
     * Payload issuer attribute
     *
     * @var string
     */
    private $issuer;

    /**
     * Payload audience attribute
     *
     * @var string
     * @todo write setter
     */
    private $audience;

    /**
     * Payload subject attribute
     *
     * @var string
     * @todo write setter
     */
    private $subject;

    /**
     * Array for generating the JWT payload
     *
     * @var array
     */
    private $payload = [];

    /**
     * Return the JWT header type string
     *
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Return the secret string for the JWT signature generation
     *
     * @return string
     */
    public function getSecret()
    {
        if (!empty($this->secret)) {
            return $this->secret;
        }

        throw new TokenBuilderException(
            'Token secret not set, please add a secret to increase security'
        );
    }

    /**
     * Check the expiration object is valid and return the JWT expiration
     * attribute as a Carbon object
     *
     * @return Carbon\Carbon
     */
    public function getExpiration()
    {
        if (!$this->hasOldExpiration()) {
            return $this->expiration;
        }

        throw new TokenBuilderException(
            'Token expiration date has already expired, please set a future expiration date'
        );
    }

    /**
     * Return the JWT issuer attribute string
     *
     * @return string
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * Return the JWT audience attribute string
     *
     * @return string
     * @todo write setter
     */
    public function getAudience()
    {
        return $this->audience;
    }

    /**
     * Return the JWT subject attribute string
     *
     * @return string
     * @todo write setter
     */
    public function getSubject()
    {
        return $this->subject;
    }

    /**
     * Json encode and return the JWT Header
     *
     * @return string
     */
    public function getHeader()
    {
        return json_encode(['alg' => $this->getAlgorithm(), 'typ' => $this->getType()]);
    }

    /**
     * Json encode and return the JWT Payload
     *
     * @return string
     */
    public function getPayload()
    {
        if (!array_key_exists('iss', $this->payload)) {
            $this->payload = array_merge($this->payload, ['iss' => $this->getIssuer()]);
            $this->payload = array_merge($this->payload, ['exp' => $this->getExpiration()->toDateTimeString()]);
            $this->payload = array_merge($this->payload, ['sub' => $this->getSubject()]);
            $this->payload = array_merge($this->payload, ['aud' => $this->getAudience()]);
        }

        return json_encode($this->payload);
    }

    /**
     * Generate and return the JWT signature object
     *
     * @return Signature
     */
    public function getSignature()
    {
        return new Signature($this->getHeader(), $this->getPayload(), $this->getSecret(), $this->getHash());
    }

    /**
     * Set the secret for the JWT Signature, return the Token Builder
     *
     * @return TokenBuilder
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * Parse a date time string to a Carbon object to set the expiration for the
     * JWT Payload, return the Token Builder
     *
     * @return TokenBuilder
     */
    public function setExpiration($expiration)
    {
        $this->expiration = DateTime::parse($expiration);

        return $this;
    }

    /**
     * Set the issuer for the JWT issuer, return the Token Builder
     *
     * @return TokenBuilder
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;

        return $this;
    }

    /**
     * Add key value pair to payload array
     *
     * @return TokenBuilder
     */
    public function addPayload($key, $value)
    {
        $this->payload = array_merge($this->payload, [$key => $value]);

        return $this;
    }

    private function encodeHeader()
    {
        return TokenEncodeDecode::encode($this->getHeader());
    }

    /**
     * Check for payload, if it exists encode and return payload
     *
     * @return string
     */
    private function encodePayload()
    {
        if (!empty($this->issuer) && !empty($this->expiration)) {
            return TokenEncodeDecode::encode($this->getPayload());
        }

        throw new TokenBuilderException(
            'Token cannot be built please add a payload, including an issuer and an expiration.'
        );
    }

    /**
     * Build and return the JSON Web Token
     *
     * @return string
     */
    public function build()
    {
        return $this->encodeHeader() . "." .
            $this->encodePayload() . "." .
            $this->getSignature()->get();
    }

    /**
     * Check that the expiration Carbon object is not an old date
     *
     * @return boolean
     */
    private function hasOldExpiration()
    {
        return DateTime::olderThan(DateTime::now(), DateTime::parse($this->expiration));
    }
}
