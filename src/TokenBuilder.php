<?php namespace ReallySimpleJWT;

use ReallySimpleJWT\Exception\TokenBuilderException;
use ReallySimpleJWT\Helper\Signature;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
use ReallySimpleJWT\Helper\DateTime;
use Carbon\Carbon;
use ReallySimpleJWT\Helper\Secret;

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
     * @var Carbon
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
     */
    private $audience;

    /**
     * Payload subject attribute
     *
     * @var string
     */
    private $subject;

    /**
     * Array for generating the JWT header
     *
     * @var array
     */
    private $header = [];


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
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Return the secret string for the JWT signature generation
     *
     * @return string
     */
    public function getSecret(): string
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
     * @return Carbon
     */
    public function getExpiration(): Carbon
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
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Return the JWT audience attribute string
     *
     * @return string
     */
    public function getAudience(): string
    {
        return empty($this->audience) ? '' : $this->audience;
    }

    /**
     * Set the audience of the token
     *
     * @param string $audience
     */
    public function setAudience(string $audience)
    {
        $this->audience = $audience;
    }

    /**
     * Return the JWT subject attribute string
     *
     * @return string
     */
    public function getSubject(): string
    {
        return empty($this->subject) ? '' : $this->subject;
    }

    /**
     * Set the subject of the token
     *
     * @param string $subject
     */
    public function setSubject(string $subject)
    {
        $this->subject = $subject;
    }

    /**
     * Json encode and return the JWT Header
     *
     * @return string
     */
    public function getHeader(): string
    {
        $header = array_merge($this->header, ['alg' => $this->getAlgorithm(), 'typ' => $this->getType()]);

        return json_encode($header);
    }

    /**
     * Json encode and return the JWT Payload
     *
     * @return string
     */
    public function getPayload(): string
    {
        if (!array_key_exists('iss', $this->payload)) {
            $this->payload = array_merge($this->payload, ['iss' => $this->getIssuer()]);
            $this->payload = array_merge($this->payload, ['exp' => $this->getExpiration()->getTimestamp()]);
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
    public function getSignature(): Signature
    {
        return new Signature($this->getHeader(), $this->getPayload(), $this->getSecret(), $this->getHash());
    }

    /**
     * Set the secret for the JWT Signature, return the Token Builder
     *
     * @param string $secret
     *
     * @return TokenBuilder
     */
    public function setSecret(string $secret): TokenBuilder
    {
        Secret::validate($secret);

        $this->secret = $secret;

        return $this;
    }

    /**
     * Parse a date time string to a Carbon object to set the expiration for the
     * JWT Payload, return the Token Builder
     *
     * @param mixed $expiration
     *
     * @return TokenBuilder
     */
    public function setExpiration($expiration): TokenBuilder
    {
        if (is_numeric($expiration)) {
            $this->expiration = DateTime::createFromTimestamp((int) $expiration);
            return $this;
        }

        $this->expiration = DateTime::parse($expiration);
        return $this;
    }

    /**
     * Set the issuer for the JWT issuer, return the Token Builder
     *
     * @param string $issuer
     *
     * @return TokenBuilder
     */
    public function setIssuer(string $issuer): TokenBuilder
    {
        $this->issuer = $issuer;

        return $this;
    }

    /**
     * Add key value pair to payload array
     *
     * @param array $payload
     *
     * @return TokenBuilder
     */
    public function addPayload(array $payload): TokenBuilder
    {
        if (isset($payload['key']) && isset($payload['value'])) {
            $this->payload = array_merge($this->payload, [$payload['key'] => $payload['value']]);

            return $this;
        }

        throw new TokenBuilderException('Failed to add payload, format wrong. Array must contain key and value.');
    }

    /**
     * Add key value pair to header array
     *
     * @param array $header
     *
     * @return TokenBuilder
     */
    public function addHeader(array $header): TokenBuilder
    {
        if (isset($header['key']) && isset($header['value'])) {
            $this->header = array_merge($this->header, [$header['key'] => $header['value']]);

            return $this;
        }

        throw new TokenBuilderException('Failed to add header, format wrong. Array must contain key and value.');
    }

    /**
     * Encode the header string and return it
     *
     * @return string
     */
    private function encodeHeader(): string
    {
        return TokenEncodeDecode::encode($this->getHeader());
    }

    /**
     * Check for payload, if it exists encode and return payload
     *
     * @return string
     */
    private function encodePayload(): string
    {
        if (!empty($this->issuer) && !empty($this->expiration)) {
            return TokenEncodeDecode::encode($this->getPayload());
        }

        throw new TokenBuilderException(
            'Token cannot be built please add a payload, including an issuer and an expiration.'
        );
    }

    /**
     * Build and return the JSON Web Token, then tear down / reset class
     *
     * @return string
     */
    public function build(): string
    {
        $jwt = $this->encodeHeader() . "." .
            $this->encodePayload() . "." .
            $this->getSignature()->get();

        $this->tearDown();

        return $jwt;
    }

    /**
     * Check that the expiration Carbon object is not an old date
     *
     * @return bool
     */
    private function hasOldExpiration(): bool
    {
        return DateTime::olderThan(DateTime::now(), DateTime::parse($this->expiration));
    }

    /**
     * This method resets the class state after the build method is called.
     */
    private function tearDown()
    {
        $this->header = [];
        $this->payload = [];
        $this->secret = '';
        $this->expiration = new Carbon;
        $this->issuer = '';
        $this->subject = '';
        $this->audience = '';
    }
}
