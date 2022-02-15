<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Encoders\EncodeHS256Strong;
use ReallySimpleJWT\Exception\TokensException;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Exception\JwtException;
use ReallySimpleJWT\Exception\ParsedException;

/**
 * Core factory and interface class for creating basic JSON Web Tokens.
 */
class Tokens
{
    /**
     * Factory method to return an instance of the Build class for creating new
     * JSON Web Tokens.
     */
    public function builder(string $secret): Build
    {
        return new Build(
            'JWT',
            new Validator(),
            new EncodeHS256Strong($secret)
        );
    }

    /**
     * Factory method to return an instance of the Parse class for
     * parsing a JWT.
     */
    public function parser(string $token): Parse
    {
        return new Parse(
            new Jwt($token),
            new Decode()
        );
    }

    /**
     * Factory method to return an instance of the Validate class to validate
     * the structure, signature and claims data of a JWT.
     */
    public function validator(string $token, string $secret = ''): Validate
    {
        return new Validate(
            $this->parser($token)->parse(),
            new EncodeHS256($secret),
            new Validator()
        );
    }

    /**
     * Return the header claims data from a JWT.
     *
     * @return mixed[]
     */
    public function getHeader(string $token): array
    {
        try {
            $parser = $this->parser($token);
            return $parser->parse()->getHeader();
        } catch (JwtException $e) {
            return [];
        }
    }

    /**
     * Return the payload claims data from a JWT.
     *
     * @return mixed[]
     */
    public function getPayload(string $token): array
    {
        try {
            $parser = $this->parser($token);
            return $parser->parse()->getPayload();
        } catch (JwtException $e) {
            return [];
        }
    }

    /**
     * Create a basic JSON Web Token for a user, define the user key and id to
     * identify the user along with an expiration and issuer.
     *
     * @param string|int $userId
     */
    public function create(string $userKey, string|int $userId, string $secret, int $expiration, string $issuer): Jwt
    {
        $builder = $this->builder($secret);

        return $builder->setPayloadClaim($userKey, $userId)
            ->setExpiration($expiration)
            ->setIssuer($issuer)
            ->setIssuedAt(time())
            ->build();
    }

    /**
     * Create a basic token based on an array of payload claims.
     * Format [string: mixed].
     *
     * @param mixed[] $payload
     */
    public function customPayload(array $payload, string $secret): Jwt
    {
        $builder = $this->builder($secret);

        foreach ($payload as $key => $value) {
            if (is_int($key)) {
                throw new TokensException('Invalid payload claim.', 8);
            }

            $builder->setPayloadClaim($key, $value);
        }

        return $builder->build();
    }

    /**
     * Validate the token structure and signature.
     */
    public function validate(string $token, string $secret): bool
    {
        try {
            $validate = $this->validator($token, $secret);
            $validate->algorithmNotNone()
                ->signature();
            return true;
        } catch (ValidateException $e) {
            return false;
        } catch (JwtException $e) {
            return false;
        }
    }

    /**
     * Validate the expiration claim of a token to see if it has expired. Will
     * return false if the expiration (exp) claim is not set.
     */
    public function validateExpiration(string $token): bool
    {
        $validate = $this->validator($token);

        try {
            $validate->expiration();
            return true;
        } catch (ValidateException $e) {
            return false;
        } catch (ParsedException $e) {
            return false;
        }
    }

    /**
     * Validate the not before claim of a token to see if it is ready to use.
     * Will return false if the not before (nbf) claim is not set.
     */
    public function validateNotBefore(string $token): bool
    {
        $validate = $this->validator($token);

        try {
            $validate->notBefore();
            return true;
        } catch (ValidateException $e) {
            return false;
        } catch (ParsedException $e) {
            return false;
        }
    }
}
