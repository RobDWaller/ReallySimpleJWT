<?php namespace ReallySimpleJWT\Helper;

use Carbon\Carbon;
use ReallySimpleJWT\Exception\TokenDateException;
use Exception;

/**
 * A Date Time class that provides and interface to the Carbon Date Time library
 */
class DateTime
{
    /**
     * Return a Carbon object based on the current date
     *
     * @return Carbon
     */
    public static function now(): Carbon
    {
        return Carbon::now();
    }

    /**
     * Return a Carbon object based on a unix timestamp
     *
     * @param int $timestamp
     * @return Carbon
     */
    public static function createFromTimestamp(int $timestamp): Carbon
    {
        return Carbon::createFromTimestamp($timestamp);
    }

    /**
     * Parse a date time string and return a Carbon object based on the date
     * time string.
     *
     * @param string $dateTimeString
     *
     * @return Carbon
     */
    public static function parse(string $dateTimeString): Carbon
    {
        self::isEmptyDateTimeString($dateTimeString);

        try {
            return Carbon::parse($dateTimeString);
        } catch (Exception $e) {
            throw new TokenDateException(
                'The date time string [' . $dateTimeString . '] you attempted to parse is invalid.'
            );
        }
    }

    /**
     * Check whether the date time string is empty or not
     *
     * @param string $dateTimeString
     *
     * @return bool
     */
    private static function isEmptyDateTimeString(string $dateTimeString): bool
    {
        if (!empty($dateTimeString)) {
            return true;
        }

        throw new TokenDateException(
            'The date time string [' . $dateTimeString . '] you attempted to parse is empty.'
        );
    }

    /**
     * Check whether one Carbon object is older than another Carbon object
     *
     * @param Carbon $baseDate
     * @param Carbon $comparisonDate
     *
     * @return bool
     */
    public static function olderThan(Carbon $baseDate, Carbon $comparisonDate): bool
    {
        return $baseDate->diffInSeconds($comparisonDate, false) < 0;
    }
}
