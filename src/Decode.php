<?php

namespace ReallySimpleJWT;

use ReallySimpleJWT\Interfaces\Decode as DecodeInterface;
use ReallySimpleJWT\Helper\Base64;
use ReallySimpleJWT\Helper\JsonEncoder;

class Decode implements DecodeInterface
{
    use Base64;
    use JsonEncoder;

    /**
     * Decode a Base64 Url string to a json string
     */
    private function urlDecode(string $toDecode): string
    {
        return (string) base64_decode(
            $this->addPadding($this->toBase64($toDecode)),
            true
        );
    }

    /**
     * @return mixed[]
     */
    public function decode(string $toDecode): array
    {
        return $this->jsonDecode($this->urlDecode($toDecode));
    }
}
