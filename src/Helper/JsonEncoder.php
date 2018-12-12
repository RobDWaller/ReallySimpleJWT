<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Helper;

trait JsonEncoder
{
    public function jsonEncode(array $jsonArray): string
    {
        return (string) json_encode($jsonArray);
    }

    public function jsonDecode(string $json): array
    {
        return json_decode($json, true);
    }
}
