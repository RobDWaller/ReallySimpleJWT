<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Build;
use ReallySimpleJWT\Helper\Validator;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Signature;
use ReallySimpleJWT\Encoders\EncodeHs256;
use ReallySimpleJWT\Decoders\DecodeHs256;
use ReallySimpleJWT\Parse;
use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Exception\ValidateException;

class Tokens
{
    public function builder(): Build
    {
        return new Build(
            'JWT',
            new Validator(),
            new Secret(),
            new EncodeHs256()
        );
    }

    public function parser(string $token, string $secret): Parse
    {
        return new Parse(
            new Jwt(
                $token,
                $secret
            ),
            new DecodeHs256()
        );
    }

    public function validator(string $token, string $secret): Validate
    {
        $parse = $this->parser($token, $secret);

        return new Validate(
            $parse,
            new Signature(
                new EncodeHs256()
            ),
            new Validator()
        );
    }

    /**
     * @return mixed[]
     */
    public function getHeader(string $token, string $secret): array
    {
        $parser = $this->parser($token, $secret);
        return $parser->parse()->getHeader();
    }

    /**
     * @return mixed[]
     */
    public function getPayload(string $token, string $secret): array
    {
        $parser = $this->parser($token, $secret);
        return $parser->parse()->getPayload();
    }

    /**
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
     * @param mixed[] $payload
     */
    public function customPayload(array $payload, string $secret): Jwt
    {
        $builder = $this->builder();

        foreach ($payload as $key => $value) {
            if (is_int($key)) {
                throw new ValidateException('Invalid payload claim.', 8);
            }

            $builder->setPayloadClaim($key, $value);
        }

        return $builder->setSecret($secret)
            ->build();
    }

    public function validate(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->structure();
            $validate->signature();
            return true;
        } catch (ValidateException $e) {
            return false;
        }
    }

    public function validateExpiration(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->expiration();
            return true;
        } catch (ValidateException $e) {
            return false;
        }
    }

    public function validateNotBefore(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->notBefore();
            return true;
        } catch (ValidateException $e) {
            return false;
        }
    }
}
