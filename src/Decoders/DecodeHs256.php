<?php

namespace ReallySimpleJWT\Decoders;

use ReallySimpleJWT\Interfaces\Decode;
use ReallySimpleJWT\Helper\Base64;
use ReallySimpleJWT\Helper\JsonEncoder;

class DecodeHs256 implements Decode
{
    use Base64, JsonEncoder;

    /**
     * Decode a Base64 Url string to a json string
     *
     * @param string $toDecode
     * @return string
     */
    private function urlDecode(string $toDecode): string
    {
        return (string) base64_decode(
            $this->addPadding($this->toBase64($toDecode)),
            true
        );
    }

    public function decode(string $toDecode): array
    {
        return $this->jsonDecode($this->urlDecode($toDecode));
    }
}