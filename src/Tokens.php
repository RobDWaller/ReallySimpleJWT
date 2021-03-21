<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Decode;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Exception\TokensException;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Exception\ParseException;

/**
 * Core factory and interface class for creating basic JSON Web Tokens.
 */
class Tokens
{
    /**
     * Factory method to return an instance of the Build class for creating new
     * JSON Web Tokens.
     */
    public function builder(): Build
    {
        return new Build(
            'JWT',
            new Validator(),
            new Secret(),
            new EncodeHS256()
        );
    }

    /**
     * Factory method to return an instance of the Parse class for parsing a JWT
     * and gaining access to the token's header and payload claims data.
     */
    public function parser(string $token, string $secret): Parse
    {
        return new Parse(
            new Jwt(
                $token,
                $secret
            ),
            new Decode()
        );
    }

    /**
     * Factory method to return an instance of the Validate class to validate
     * the structure, signature and claims data of a JWT.
     */
    public function validator(string $token, string $secret): Validate
    {
        $parse = $this->parser($token, $secret);

        return new Validate(
            $parse,
            new EncodeHS256(),
            new Validator()
        );
    }

    /**
     * Return the header claims data from a JWT.
     *
     * @return mixed[]
     */
    public function getHeader(string $token, string $secret): array
    {
        $parser = $this->parser($token, $secret);
        return $parser->parse()->getHeader();
    }

    /**
     * Return the payload claims data from a JWT.
     *
     * @return mixed[]
     */
    public function getPayload(string $token, string $secret): array
    {
        $parser = $this->parser($token, $secret);
        return $parser->parse()->getPayload();
    }

    /**
     * Create a basic JSON Web Token for a user, define the user key and id to
     * identify the user along with an expiration and issuer.
     *
     * @param string|int $userId
     */
    public function create(string $userKey, $userId, string $secret, int $expiration, string $issuer): Jwt
    {
        $builder = $this->builder();

        return $builder->setPayloadClaim($userKey, $userId)
            ->setSecret($secret)
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
        $builder = $this->builder();

        foreach ($payload as $key => $value) {
            if (is_int($key)) {
                throw new TokensException('Invalid payload claim.', 8);
            }

            $builder->setPayloadClaim($key, $value);
        }

        return $builder->setSecret($secret)
            ->build();
    }

    /**
     * Validate the token structure and signature.
     */
    public function validate(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->structure()
                ->algorithmNotNone()
                ->signature();
            return true;
        } catch (ValidateException $e) {
            return false;
        }
    }

    /**
     * Validate the expiration claim of a token to see if it has expired. Will
     * return false if the expiration (exp) claim is not set.
     */
    public function validateExpiration(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->expiration();
            return true;
        } catch (ValidateException $e) {
            return false;
        } catch (ParseException $e) {
            return false;
        }
    }

    /**
     * Validate the not before claim of a token to see if it is ready to use.
     * Will return false if the not before (nbf) claim is not set.
     */
    public function validateNotBefore(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->notBefore();
            return true;
        } catch (ValidateException $e) {
            return false;
        } catch (ParseException $e) {
            return false;
        }
    }
}
