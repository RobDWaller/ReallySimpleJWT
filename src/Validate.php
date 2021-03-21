<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Interfaces\Validator;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Interfaces\Encode;

/**
 * Core validation class for ensuring a token and its claims are valid.
 */
class Validate
{
    private Parse $parse;

    private Encode $encode;

    private Validator $validate;

    public function __construct(Parse $parse, Encode $encode, Validator $validate)
    {
        $this->parse = $parse;

        $this->encode = $encode;

        $this->validate = $validate;
    }

    /**
     * Validate the JWT has the correct structure.
     *
     * @throws ValidateException
     */
    public function structure(): Validate
    {
        if (!$this->validate->structure($this->parse->getToken())) {
            throw new ValidateException('Token is invalid.', 1);
        }

        return $this;
    }

    /**
     * Validate the JWT's expiration claim (exp). This claim defines how long a
     * token can be used for.
     *
     * @throws ValidateException
     */
    public function expiration(): Validate
    {
        if (!$this->validate->expiration($this->parse->getExpiration())) {
            throw new ValidateException('Expiration claim has expired.', 4);
        }

        return $this;
    }

    /**
     * Validate the JWT's not before claim (nbf). This claim defines when a
     * token can be used from.
     *
     * @throws ValidateException
     */
    public function notBefore(): Validate
    {
        if (!$this->validate->notBefore($this->parse->getNotBefore())) {
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
        if (!$this->validate->audience($this->parse->getAudience(), $check)) {
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
        if (!$this->validate->algorithm($this->parse->getAlgorithm(), $algorithms)) {
            throw new ValidateException(
                'Algorithm claim is not valid.',
                12
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
        if ($this->validate->algorithm(strtolower($this->parse->getAlgorithm()), ['none'])) {
            throw new ValidateException(
                'Algorithm claim should not be none.',
                14
            );
        }

        return $this;
    }

    /**
     * Validate the JWT's signature. The signature taken from the JWT should
     * match a new one generated from the JWT header and payload, and secret.
     *
     * @throws ValidateException
     */
    public function signature(): Validate
    {
        $signature = $this->encode->signature(
            $this->parse->getDecodedHeader(),
            $this->parse->getDecodedPayload(),
            $this->parse->getSecret()
        );

        if (!$this->validate->signature($signature, $this->parse->getSignature())) {
            throw new ValidateException('Signature is invalid.', 3);
        }

        return $this;
    }
}
