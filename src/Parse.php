<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Jwt;
use ReallySimpleJWT\Validate;
use ReallySimpleJWT\Parsed;
use ReallySimpleJWT\Helper\TokenEncodeDecode;
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
            json_decode('{"typ": "JWT"}'),
            $this->getPayload()
        );
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
}
