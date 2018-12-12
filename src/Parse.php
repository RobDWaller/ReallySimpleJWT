<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
use ReallySimpleJWT\Helper\Signature;
use ReallySimpleJWT\Exception\Validate as ValidateException;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Helper\JsonEncoder;
use stdClass;

class Parse
{
    use JsonEncoder;

    private $jwt;

    private $validate;

    private $encode;

    public function __construct(Jwt $jwt, Validate $validate, Encode $encode)
    {
        $this->jwt = $jwt;

        $this->validate = $validate;

        $this->encode = $encode;
    }

    public function parse(): Parsed
    {
        return new Parsed(
            $this->jwt,
            $this->jsonDecode($this->encode->decode($this->getHeader())),
            $this->jsonDecode($this->encode->decode($this->getPayload())),
            $this->getSignature()
        );
    }

    public function validate(): self
    {
        if (!$this->validate->structure($this->jwt->getToken())) {
            throw new ValidateException('The JSON web token has an invalid structure.');
        }

        try {
            $signature = $this->encode->signature(
                $this->encode->decode($this->getHeader()),
                $this->encode->decode($this->getPayload()),
                $this->jwt->getSecret()
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
        return $this->jsonDecode($this->encode->decode(
            $this->getPayload()
        ))['exp'] ?? 0;
    }
}
