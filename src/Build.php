<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Encode;
use ReallySimpleJWT\Helper\JsonEncoder;
use ReallySimpleJWT\Exception\ValidateException;

class Build
{
    use JsonEncoder;

    private $payload = [];

    private $header = [];

    private $validate;

    private $secret;

    private $encode;

    private $type;

    public function __construct(string $type, Validate $validate, Encode $encode)
    {
        $this->type = $type;

        $this->validate = $validate;

        $this->encode = $encode;
    }

    public function setContentType(string $contentType): self
    {
        $this->header['cty'] = $contentType;

        return $this;
    }

    public function setHeaderClaim(string $key, $value): self
    {
        $this->header[$key] = $value;

        return $this;
    }

    public function getHeader(): array
    {
        return array_merge(
            $this->header,
            ['alg' => $this->encode->getAlgorithm(), 'typ' => $this->type]
        );
    }

    public function setSecret(string $secret): self
    {
        if (!$this->validate->secret($secret)) {
            throw new ValidateException(
                'Please set a valid secret. It must be at least twelve characters in length,
                contain lower and upper case letters,
                a number and one of the following characters *&!@%^#$.'
            );
        }

        $this->secret = $secret;

        return $this;
    }

    public function setIssuer(string $issuer): self
    {
        $this->payload['iss'] = $issuer;

        return $this;
    }

    public function setSubject(string $subject): self
    {
        $this->payload['sub'] = $subject;

        return $this;
    }

    public function setAudience($audience): self
    {
        if (is_string($audience) || is_array($audience)) {
            $this->payload['aud'] = $audience;

            return $this;
        }

        throw new ValidateException('Token audience must be either a string or array of strings.');
    }

    public function setExpiration(int $timestamp): self
    {
        if (!$this->validate->expiration($timestamp)) {
            throw new ValidateException('The expiration timestamp you set has already expired.');
        }

        $this->payload['exp'] = $timestamp;

        return $this;
    }

    public function setNotBefore(int $notBefore): self
    {
        $this->payload['nbf'] = $notBefore;

        return $this;
    }

    public function setIssuedAt(int $issuedAt): self
    {
        $this->payload['iat'] = $issuedAt;

        return $this;
    }

    public function setJwtId(string $jwtId): self
    {
        $this->payload['jti'] = $jwtId;

        return $this;
    }

    public function setPrivateClaim(string $key, $value): self
    {
        $this->payload[$key] = $value;

        return $this;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }

    public function build(): Jwt
    {
        return new Jwt(
            $this->encode->encode($this->jsonEncode($this->getHeader())) . "." .
            $this->encode->encode($this->jsonEncode($this->getPayload())) . "." .
            $this->getSignature(),
            $this->secret
        );
    }

    public function reset(): self
    {
        $this->payload = [];
        $this->header = [];
        $this->secret = '';

        return $this;
    }

    private function getSignature(): string
    {
        if (!empty($this->secret)) {
            return $this->encode->signature(
                $this->jsonEncode($this->getHeader()),
                $this->jsonEncode($this->getPayload()),
                $this->secret
            );
        }

        throw new ValidateException('Please set a valid secret for your token.');
    }
}
