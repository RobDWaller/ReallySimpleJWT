<?php namespace ReallySimpleJWT\Helper;

use ReallySimpleJWT\Helper\Base64;
use ReallySimpleJWT\Helper\Base64UrlConverter;

class TokenEncodeDecode
{
    public static function encode($preEncodeTokenString)
    {
        $base64Url = new Base64UrlConverter();

        return $base64Url->setBase64String(Base64::encode($preEncodeTokenString))
            ->toBase64Url()
            ->getBase64UrlString();
    }

    public static function decode($postEncodeTokenString)
    {
        $base64Url = new Base64UrlConverter();

        return Base64::decode(
            $base64Url->setBase64UrlString($postEncodeTokenString)
            ->toBase64()
            ->getBase64String()
        );
    }
}
