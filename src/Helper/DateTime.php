<?php namespace ReallySimpleJWT\Helper;

use Carbon\Carbon;
use ReallySimpleJWT\Exception\TokenDateException;
use Exception;

class DateTime
{
	public static function now()
	{
		return Carbon::now();
	}

	public static function parse($dateTimeString)
	{
		Self::emptyDateTimeString($dateTimeString);

		try {
			return Carbon::parse($dateTimeString);	
		}
		catch (Exception $e) {
			throw new TokenDateException(
				'The date time string [' . $dateTimeString . '] you attempted to parse is invalid.'
			);
		}
	}

	private static function emptyDateTimeString($dateTimeString)
	{
		if (!empty($dateTimeString)) {
			return true;
		}

		throw new TokenDateException(
			'The date time string [' . $dateTimeString . '] you attempted to parse is empty.'
		);
	}

	public static function olderThan(Carbon $baseDate, Carbon $comparisonDate)
	{
		return $baseDate->diffInSeconds($comparisonDate, false) < 0;
	}
}