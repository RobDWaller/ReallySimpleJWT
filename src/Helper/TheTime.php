<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Helper;

trait TheTime
{
    public function getTheTime(): int
    {
        return time();
    }
}
