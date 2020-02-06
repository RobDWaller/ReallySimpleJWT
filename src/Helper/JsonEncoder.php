<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Helper;

/**
 * A helper trait to encode and decode json.
 */
trait JsonEncoder
{
    /**
     * Consumes an associative array of data and returns a json string. Will
     * return the string 'false' if it fails to encode.
     *
     * @param array $jsonArray
     * @return string
     */
    public function jsonEncode(array $jsonArray): string
    {
        return (string) json_encode($jsonArray);
    }

    /**
     * Consumes a json string and decodes it, will always return an
     * associative array.
     *
     * @param string $json
     * @return array
     */
    public function jsonDecode(string $json): array
    {
        return (array) json_decode($json, true);
    }
}
