<?php namespace ReallySimpleJWT\Helper;

/**
 * Simple class that provides an interface for php Base 64 encoding methods
 *
 * @author Rob Waller <rdwaller1984@gmail.com>
 */
class Base64
{
    /**
     * Encode a string to a Base 64 string
     *
     * @param string $string
     *
     * @return string
     */
    public static function encode(string $string): string
    {
        return base64_encode($string);
    }

    /**
     * Decode a Base 64 string to a string
     *
     * @param string $base64String
     *
     * @return string
     */
    public static function decode(string $base64String): string
    {
        return base64_decode($base64String);
    }
}
