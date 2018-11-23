<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
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
            $this->getHeader(),
            $this->getPayload()
        );
    }

    public function validate(): self
    {
        if (!$this->validate->tokenStructure($this->jwt->getToken())) {
            throw new ValidateException('The JSON web token has an invalid structure');
        }

        return $this;
    }

    private function splitToken(): array
    {
        return explode('.', $this->jwt->getToken());
    }

    private function getPayload(): stdClass
    {
        return json_decode(
            TokenEncodeDecode::decode(
                $this->splitToken()[1]
            )
        );
    }

    private function getHeader(): stdClass
    {
        return json_decode(
            TokenEncodeDecode::decode(
                $this->splitToken()[0]
            )
        );
    }
}
