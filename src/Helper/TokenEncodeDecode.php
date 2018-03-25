<?php namespace ReallySimpleJWT\Helper;

use ReallySimpleJWT\Helper\Base64;
use ReallySimpleJWT\Helper\Base64UrlConverter;

/**
 * A class that encodes and decodes JSON to base64 Url string for the JWT creation
 *
 * @author Rob Waller <rdwaller1984@googlemail.com>
 */
class TokenEncodeDecode
{
    /**
     * Encode a JSON string to a base64 Url string
     *
     * @param string $jsonTokenString
     *
     * @return string
     */
    public static function encode(string $jsonTokenString): string
    {
        $base64Url = new Base64UrlConverter();

        return $base64Url->setBase64String(Base64::encode($jsonTokenString))
            ->toBase64Url()
            ->getBase64UrlString();
    }

    /**
     * Decode a base64 Url string to a JSON string
     *
     * @param string $base64UrlString
     *
     * @return string
     */
    public static function decode(string $base64UrlString): string
    {
        $base64Url = new Base64UrlConverter();

        return Base64::decode(
            $base64Url->setBase64UrlString($base64UrlString)
            ->toBase64()
            ->getBase64String()
        );
    }
}
