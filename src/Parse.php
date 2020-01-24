<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Interfaces\Encoder;
use ReallySimpleJWT\Helper\JsonEncoder;

/**
 * This class parses and validates a JSON Web Token. The token is housed in
 * the JWT value object. The class outputs a Parsed value object to give
 * access to the data held within the JSON Web Token.
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 */
class Parse
{
    /**
     * This is a trait to tidy away the JSON encode / decode functionality.
     * exposes the methods jsonEncode and jsonDecode to class.
     */
    use JsonEncoder;

    /**
     * The JSON Web Token value object.
     *
     * @var Jwt
     */
    private $jwt;

    /**
     * A class of validate helper methods.
     *
     * @var Validate
     */
    private $validate;

    /**
     * A class to decode JWT tokens.
     *
     * @var Interfaces\Encoder
     */
    private $encode;

    /**
     * Parse constructor
     *
     * @param Jwt $jwt
     * @param Validate $validate
     * @param Encoder $encode
     */
    public function __construct(Jwt $jwt, Validate $validate, Encoder $encode)
    {
        $this->jwt = $jwt;

        $this->validate = $validate;

        $this->encode = $encode;
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
        if (!$this->validate->structure($this->jwt->getToken())) {
            throw new ValidateException('Token is invalid.', 1);
        }

        $this->validateSignature();

        return $this;
    }

    /**
     * Validate the JWT's expiration claim in the payload is valid, if the
     * expiration has expired it will throw an exception.
     *
     * @return Parse
     * @throws ValidateException
     */
    public function validateExpiration(): self
    {
        if (!$this->validate->expiration($this->getExpiration())) {
            throw new ValidateException('Expiration claim has expired.', 4);
        }

        return $this;
    }

    /**
     * Validate the JWT's not before claim in the payload is valid, if the
     * not before time has not elapsed it will throw an exception.
     *
     * @return Parse
     * @throws ValidateException
     */
    public function validateNotBefore(): self
    {
        if (!$this->validate->notBefore($this->getNotBefore())) {
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
    public function validateAudience(string $check): self
    {
        if (!$this->validate->audience($this->getAudience(), $check)) {
            throw new ValidateException(
                'Audience claim does not contain provided StringOrURI.',
                2
            );
        }

        return $this;
    }

    /**
     * Generate the Parsed Value Object. This method should be called last
     * after the relevant validate methods have been called.
     *
     * @return Parsed
     */
    public function parse(): Parsed
    {
        return new Parsed(
            $this->jwt,
            $this->decodeHeader(),
            $this->decodePayload(),
            $this->getSignature()
        );
    }

    /**
     * Validate the JWT's signature. The provided signature taken from the JWT
     * should match one newly generated from the JWT header and payload.
     *
     * @throws ValidateException
     */
    private function validateSignature(): void
    {
        $signature = $this->encode->signature(
            $this->encode->decode($this->getHeader()),
            $this->encode->decode($this->getPayload()),
            $this->jwt->getSecret()
        );

        if (!$this->validate->signature($signature, $this->getSignature())) {
            throw new ValidateException('Signature is invalid.', 3);
        }
    }

    /**
     * Split the JWT into it's component parts, the header, payload and
     * signature are all separated by a dot.
     *
     * @return array
     */
    private function splitToken(): array
    {
        return explode('.', $this->jwt->getToken());
    }

    /**
     * Get the header string from the JWT string. This is the first part of the
     * JWT string.
     *
     * @return string
     */
    private function getHeader(): string
    {
        return $this->splitToken()[0] ?? '';
    }

    /**
     * Get the payload string from the JWT string. This is the second part of
     * the JWT string.
     *
     * @return string
     */
    private function getPayload(): string
    {
        return $this->splitToken()[1] ?? '';
    }

    /**
     * Get the signature string from the JWT string. This is the third part of
     * the JWT string.
     *
     * @return string
     */
    private function getSignature(): string
    {
        return $this->splitToken()[2] ?? '';
    }

    /**
     * Retireve the expiration claim from the JWT.
     *
     * @return int
     * @throws ValidateException
     */
    private function getExpiration(): int
    {
        if (isset($this->decodePayload()['exp'])) {
            return $this->decodePayload()['exp'];
        }

        throw new ValidateException('Expiration claim is not set.', 6);
    }

    /**
     * Retireve the not before claim from the JWT.
     *
     * @return int
     * @throws ValidateException
     */
    private function getNotBefore(): int
    {
        if (isset($this->decodePayload()['nbf'])) {
            return $this->decodePayload()['nbf'];
        }

        throw new ValidateException('Not Before claim is not set.', 7);
    }

    /**
     * Retireve the audience claim from the JWT.
     *
     * @return string|array
     * @throws ValidateException
     */
    private function getAudience()
    {
        if (isset($this->decodePayload()['aud'])) {
            return $this->decodePayload()['aud'];
        }

        throw new ValidateException('Audience claim is not set.', 2);
    }

    /**
     * Decode the JWT header string to an associative array.
     *
     * @return array
     */
    private function decodeHeader(): array
    {
        return $this->jsonDecode($this->encode->decode(
            $this->getHeader()
        ));
    }

    /**
     * Decode the JWT payload string to an associative array.
     *
     * @return array
     */
    private function decodePayload(): array
    {
        return $this->jsonDecode($this->encode->decode(
            $this->getPayload()
        ));
    }
}
