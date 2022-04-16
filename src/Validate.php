<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Validator;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Exception\ParsedException;
use ReallySimpleJWT\Interfaces\Encode;

/**
 * Core validation class for ensuring a token and its claims are valid.
 */
class Validate
{
    private Parsed $parsed;

    private Encode $encode;

    private Validator $validator;

    public function __construct(Parsed $parsed, Encode $encode, Validator $validator)
    {
        $this->parsed = $parsed;

        $this->encode = $encode;

        $this->validator = $validator;
    }

    /**
     * Validate the JWT's expiration claim (exp). This claim defines how long a
     * token can be used for.
     *
     * @throws ValidateException
     * @throws ParsedException
     */
    public function expiration(): Validate
    {
        if (!$this->validator->expiration($this->parsed->getExpiration())) {
            throw new ValidateException('Expiration claim has expired.', 4);
        }

        return $this;
    }

    /**
     * Validate the JWT's not before claim (nbf). This claim defines when a
     * token can be used from.
     *
     * @throws ValidateException
     * @throws ParsedException
     */
    public function notBefore(): Validate
    {
        if (!$this->validator->notBefore($this->parsed->getNotBefore())) {
            throw new ValidateException('Not Before claim has not elapsed.', 5);
        }

        return $this;
    }

    /**
     * Validate the audience claim exists and is a string or an array
     * of strings.
     *
     * @throws ValidateException
     */
    public function audience(string $check): Validate
    {
        if (!$this->validator->audience($this->parsed->getAudience(), $check)) {
            throw new ValidateException(
                'Audience claim does not contain provided StringOrURI.',
                2
            );
        }

        return $this;
    }

    /**
     * Validate the tokens alg claim is a valid digital signature or MAC
     * algorithm. Value can also be "none". See RFC 7518 for more details.
     *
     * @param string[] $algorithms
     * @throws ValidateException
     */
    public function algorithm(array $algorithms): Validate
    {
        if (!$this->validator->algorithm($this->parsed->getAlgorithm(), $algorithms)) {
            throw new ValidateException(
                'Algorithm claim is not valid.',
                10
            );
        }

        return $this;
    }

    /**
     * Validate the token's alg claim is not none.
     *
     * @throws ValidateException
     */
    public function algorithmNotNone(): Validate
    {
        if ($this->validator->algorithm(strtolower($this->parsed->getAlgorithm()), ['none'])) {
            throw new ValidateException(
                'Algorithm claim should not be none.',
                11
            );
        }

        return $this;
    }

    /**
     * Validate the JWT's signature. The signature taken from the JWT should
     * match a new one generated from the JWT header, payload and secret.
     *
     * @throws ValidateException
     */
    public function signature(): Validate
    {
        $signature = $this->encode->signature(
            $this->parsed->getHeader(),
            $this->parsed->getPayload()
        );

        if (!$this->validator->signature($signature, $this->parsed->getSignature())) {
            throw new ValidateException('Signature is invalid.', 3);
        }

        return $this;
    }
}
