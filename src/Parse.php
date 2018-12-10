<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
use ReallySimpleJWT\Helper\Signature;
use ReallySimpleJWT\Exception\Validate as ValidateException;
use stdClass;

class Parse
{
    private $jwt;

    private $validate;

    public function __construct(Jwt $jwt, Validate $validate)
    {
        $this->jwt = $jwt;

        $this->validate = $validate;
    }

    public function parse(): Parsed
    {
        return new Parsed(
            $this->jwt,
            json_decode(TokenEncodeDecode::decode($this->getHeader())),
            json_decode(TokenEncodeDecode::decode($this->getPayload())),
            $this->getSignature()
        );
    }

    public function validate(): self
    {
        if (!$this->validate->structure($this->jwt->getToken())) {
            throw new ValidateException('The JSON web token has an invalid structure.');
        }

        try {
            $signature = new Signature(
                TokenEncodeDecode::decode($this->getHeader()),
                TokenEncodeDecode::decode($this->getPayload()),
                $this->jwt->getSecret(),
                'sha256'
            );
        } catch (\Throwable $e) {
            throw new ValidateException('The JSON web token is invalid [' . $this->jwt->getToken() . '].');
        }

        if (!$this->validate->signature($signature, $this->getSignature())) {
            throw new ValidateException('The JSON web token signature is invalid.');
        }

        return $this;
    }

    public function validateExpiration(): self
    {
        if (!$this->validate->expiration($this->getExpiration())) {
            throw new ValidateException('The expiration time has elapsed or it was never set, this token is not valid.');
        }

        return $this;
    }

    private function splitToken(): array
    {
        return explode('.', $this->jwt->getToken());
    }

    private function getHeader(): string
    {
        return $this->splitToken()[0];
    }

    private function getPayload(): string
    {
        return $this->splitToken()[1];
    }

    private function getSignature(): string
    {
        return $this->splitToken()[2];
    }

    private function getExpiration(): int
    {
        return json_decode(TokenEncodeDecode::decode($this->getPayload()))->exp ?? 0;
    }
}
