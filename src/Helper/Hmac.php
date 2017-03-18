<?php namespace ReallySimpleJWT\Helper;

/**
 * A very simple class that provides an interface to the php hash_hmac method to
 * hash strings
 */
class Hmac
{
    /**
     * Hash a string
     *
     * @param string $hash
     * @param string $string
     * @param string $secret
     * @param boolean $output
     *
     * @return string
     */
    public static function hash($hash, $string, $secret, $output = true)
    {
        return hash_hmac($hash, $string, $secret, $output);
    }
}
