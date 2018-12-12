<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Exception;

use Exception;
use Throwable;

/**
 * Simple exception interface class for the Token Validator class to make
 * exceptions more specific and obvious. Extends the PHP exception class
 *
 * @author Rob Waller <rdwaller1984@gmail.com>
 */
class Validate extends Exception
{
    /**
     * Constructor for the Token Builder Exception class
     *
     * @param string $message
     * @param int $code
     * @param Throwable $previous
     */
    public function __construct(string $message, int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
