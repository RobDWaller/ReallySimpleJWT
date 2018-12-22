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

    public function validate(): self
    {
        if (!$this->validate->structure($this->jwt->getToken())) {
            $this->error('The JSON web token has an invalid structure.');
        }

        $this->validateSignature();

        return $this;
    }

    public function validateExpiration(): self
    {
        if (!$this->validate->expiration($this->getExpiration())) {
            $this->error('The expiration time has elapsed, this token is no longer valid.');
        }

        return $this;
    }

    public function validateNotBefore(): self
    {
        if (!$this->validate->notBefore($this->getNotBefore())) {
            $this->error('This token is not valid as the Not Before date/time value has not elapsed.');
        }

        return $this;
    }

    public function parse(): Parsed
    {
        return new Parsed(
            $this->jwt,
            $this->decodeHeader(),
            $this->decodePayload(),
            $this->getSignature()
        );
    }

    private function validateSignature(): void
    {
        $signature = '';

        try {
            $signature = $this->encode->signature(
                $this->encode->decode($this->getHeader()),
                $this->encode->decode($this->getPayload()),
                $this->jwt->getSecret()
            );
        } catch (\Throwable $e) {
            $this->error('The JSON web token is invalid [' . $this->jwt->getToken() . '].');
        }

        if (!$this->validate->signature($signature, $this->getSignature())) {
            $this->error('The JSON web token signature is invalid.');
        }
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
        if (isset($this->decodePayload()['exp'])) {
            return $this->decodePayload()['exp'];
        }

        $this->error('The Expiration claim was not set on this token.');
    }

    private function getNotBefore(): int
    {
        if (isset($this->decodePayload()['nbf'])) {
            return $this->decodePayload()['nbf'];
        }

        $this->error('The Not Before claim was not set on this token.');
    }

    private function decodeHeader(): array
    {
        return $this->jsonDecode($this->encode->decode(
            $this->getHeader()
        ));
    }

    private function decodePayload(): array
    {
        return $this->jsonDecode($this->encode->decode(
            $this->getPayload()
        ));
    }

    private function error(string $message): void
    {
        throw new ValidateException($message);
    }
}
