<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Validator;
use ReallySimpleJWT\Interfaces\Encode;
use ReallySimpleJWT\Exception\BuildException;

/**
 * A class to help build a JSON Web Token.
 *
 * Class contains helper methods that allow you to easily set JWT claims
 * defined in the JWT RFC. Eg setIssuer() will set the iss claim in the
 * JWT payload.
 */
class Build
{
    /**
     * Defines the type of JWT to be created, usually just JWT.
     */
    private string $type;

    /**
     * Holds the JWT header claims
     *
     * @var mixed[]
     */
    private array $header = [];

    /**
     * Holds the JWT payload claims.
     *
     * @var mixed[]
     */
    private array $payload = [];

    /**
     * Token claim validator.
     */
    private Validator $validator;

    /**
     * Token Encoder which complies with the encoder interface.
     */
    private Encode $encode;

    public function __construct(string $type, Validator $validator, Encode $encode)
    {
        $this->type = $type;

        $this->validator = $validator;

        $this->encode = $encode;
    }

    /**
     * Define the content type header claim for the JWT. This defines
     * structural information about the token. For instance if it is a
     * nested token.
     */
    public function setContentType(string $contentType): Build
    {
        $this->header['cty'] = $contentType;

        return $this;
    }

    /**
     * Add custom claims to the JWT header
     */
    public function setHeaderClaim(string $key, mixed $value): Build
    {
        $this->header[$key] = $value;

        return $this;
    }

    /**
     * Get the contents of the JWT header. This is an associative array of
     * the defined header claims. The JWT algorithm and typ are added
     * by default.
     *
     * @return mixed[]
     */
    public function getHeader(): array
    {
        return array_merge(
            $this->header,
            ['alg' => $this->encode->getAlgorithm(), 'typ' => $this->type]
        );
    }

    /**
     * Set the issuer JWT payload claim. This defines who issued the token.
     * Can be a string or URI.
     */
    public function setIssuer(string $issuer): Build
    {
        $this->payload['iss'] = $issuer;

        return $this;
    }

    /**
     * Set the subject JWT payload claim. This defines who the JWT is for.
     * Eg an application user or admin.
     */
    public function setSubject(string $subject): Build
    {
        $this->payload['sub'] = $subject;

        return $this;
    }

    /**
     * Set the audience JWT payload claim. This defines a list of 'principals'
     * who will process the JWT. Eg a website or websites who will validate
     * users who use this token. This claim can either be a single string or an
     * array of strings.
     *
     * @param string|mixed[] $audience
     * @throws BuildException
     */
    public function setAudience(string|array $audience): Build
    {
        $this->payload['aud'] = $audience;

        return $this;
    }

    /**
     * Set the expiration JWT payload claim. This sets the time at which the
     * JWT should expire and no longer be accepted.
     *
     * @throws BuildException
     */
    public function setExpiration(int $timestamp): Build
    {
        if (!$this->validator->expiration($timestamp)) {
            throw new BuildException('Expiration claim has expired.', 4);
        }

        $this->payload['exp'] = $timestamp;

        return $this;
    }

    /**
     * Set the not before JWT payload claim. This sets the time after which the
     * JWT can be accepted.
     */
    public function setNotBefore(int $notBefore): Build
    {
        $this->payload['nbf'] = $notBefore;

        return $this;
    }

    /**
     * Set the issued at JWT payload claim. This sets the time at which the
     * JWT was issued / created.
     */
    public function setIssuedAt(int $issuedAt): Build
    {
        $this->payload['iat'] = $issuedAt;

        return $this;
    }

    /**
     * Set the JSON token identifier JWT payload claim. This defines a unique
     * identifier for the token.
     */
    public function setJwtId(string $jwtId): Build
    {
        $this->payload['jti'] = $jwtId;

        return $this;
    }

    /**
     * Set a custom payload claim on the JWT. The RFC calls these private
     * claims. Eg you may wish to set a user_id or a username in the
     * JWT payload.
     */
    public function setPayloadClaim(string $key, mixed $value): Build
    {
        $this->payload[$key] = $value;

        return $this;
    }

    /**
     * Get the JWT payload. This will return an array of registered claims and
     * private claims which make up the JWT payload.
     *
     * @return mixed[]
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Build the token, this is the last method which should be called after
     * all the header and payload claims have been set. It will encode the
     * header and payload, and generate the JWT signature. It will then
     * concatenate each part with dots into a single string.
     *
     * This JWT string along with the secret are then used to generate a new
     * instance of the JWT class which is returned.
     */
    public function build(): Jwt
    {
        return new Jwt(
            $this->encode->encode($this->getHeader()) . "." .
            $this->encode->encode($this->getPayload()) . "." .
            $this->getSignature()
        );
    }

    /**
     * Generate a new token with the same initial setup. Allows you to chain the
     * creation of multiple tokens.
     */
    public function reset(): Build
    {
        return new Build(
            $this->type,
            $this->validator,
            $this->encode
        );
    }

    /**
     * Generate and return the JWT signature, this is made up of the header,
     * payload and secret.
     */
    private function getSignature(): string
    {
        return $this->encode->signature(
            $this->getHeader(),
            $this->getPayload()
        );
    }
}
