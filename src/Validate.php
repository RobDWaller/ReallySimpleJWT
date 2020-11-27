<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Interfaces\Signature;

class Validate
{
    private Parse $parse;

    private Signature $signature;

    private Validator $validate;

    public function __construct(Parse $parse, Signature $signature, Validator $validate)
    {
        $this->parse = $parse;

        $this->signature = $signature;

        $this->validate = $validate;
    }

    /**
     * Validate the JWT has the right string structure and the signature
     * is valid and has not been tampered with.
     *
     * @return Parse
     * @throws ValidateException
     */
    public function validate(): self
    {
        if (!$this->validate->structure($this->parse->getToken())) {
            throw new ValidateException('Token is invalid.', 1);
        }

        $this->signature();

        return $this;
    }

    /**
     * Validate the JWT's expiration claim (exp). This claim defines when a
     * token can be used until.
     *
     * @return Parse
     * @throws ValidateException
     */
    public function expiration(): self
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
     * @return Parse
     * @throws ValidateException
     */
    public function notBefore(): self
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
     * @return Parse
     * @throws ValidateException
     */
    public function audience(string $check): self
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
     */
    public function algorithm(array $additional = []): self
    {
        if (!$this->validate->algorithm($this->parse->getAlgorithm(), $additional)) {
            throw new ValidateException(
                'Algorithm claim is not valid.',
                12
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
    public function signature(): void
    {
        $signature = $this->signature->make(
            $this->parse->getDecodedHeader(),
            $this->parse->getDecodedPayload(),
            $this->parse->getSecret()
        );

        if (!$this->validate->signature($signature, $this->parse->getSignature())) {
            throw new ValidateException('Signature is invalid.', 3);
        }
    }
}
