<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Helper;

trait Errors
{
    public static function isExpirationError(int $code): bool
    {
        return in_array($code, [1, 2, 3, 4], true);
    }
}
