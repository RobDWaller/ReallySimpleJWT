<?php
 
use ReallySimpleJWT\Token;
use ReallySimpleJWT\TokenValidator;
use Carbon\Carbon; 

class TokenValidatorTest extends PHPUnit_Framework_TestCase
{
	public function testValidateSuccessful()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			54, 
			'ab&7dj)9)', 
			Carbon::now()->addMinutes(11)->toDateTimeString(),
			'www.mysite.com'
		);

		$this->assertTrue(
			$validator->splitToken($tokenString)
				->validateExpiration()
				->validateSignature('ab&7dj)9)')
		);
	}

	public function testGetPayload()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			'twelve123', 
			'op(9odP', 
			Carbon::now()->addMinutes(5)->toDateTimeString(),
			'www.mysite.com'
		);

		$payload = $validator->splitToken($tokenString)
			->getPayload();

		$this->assertEquals('twelve123', json_decode($payload)->user_id);
	}

	public function testValidateExpiration()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			'twelve123', 
			'op(9odP', 
			Carbon::now()->addMinutes(2)->toDateTimeString(),
			'www.mysite.com'
		);

		$payload = $validator->splitToken($tokenString)
			->validateExpiration();

		$this->assertInstanceOf('ReallySimpleJWT\TokenValidator', $payload);
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testValidateExpirationFailure()
	{
		$validator = new TokenValidator();

		$tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
		eyJ1c2VyX2lkIjoyMDE5MjMsImlzcyI6Ind3dy55b3Vyc2l0ZS5jb20iLCJleHAiOiIyMDE3
		LTAyLTIzIDA5OjIyOjExIiwic3ViIjpudWxsLCJhdWQiOm51bGx9.
		Wlkt+HRQ7MIhcl6h+ECPlAArb4YhY79GsoVIEphnhlo=';

		$validator->splitToken($tokenString)
			->validateExpiration();
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testValidateExpirationFailureBadData()
	{
		$validator = new TokenValidator();

		$tokenString = 'eyJhbGciOizI1NiIsInR5cCI6IkpXVCJ9.
		eyJ1c2VyX2lkIjoyMDE5MjMsImlzcyI6Ind3Vyc2l0ZS5jb20iLCJleHAiOiIyMDE3
		LTAyLTIzIDA5OjIyOjExIiwic3ViIsLCJhdWQiOm51bGx9.
		Wlkt+HRQ7MIhcl6h+ECPlAArb4YhY79GsoVIEphnhlo=';

		$validator->splitToken($tokenString)
			->validateExpiration();
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenDateException
	 */
	public function testValidateExpirationFailureEmptyDate()
	{
		$validator = new TokenValidator();

		$tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
		eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6IiJ9.
		4OGvHh_thMaNu0vc57AuiSqsn0mQYtNrSUvRa4mYt6M';

		$validator->splitToken($tokenString)
			->validateExpiration();
	}

		/**
	 * @expectedException ReallySimpleJWT\Exception\TokenDateException
	 */
	public function testValidateExpirationFailureBadDate()
	{
		$validator = new TokenValidator();

		$tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6ImhlbGxvIn0.
			yA4cawhobqrrsqDMFfcZkgj-c0KQ8ozuTlDFebTkujs';

		$validator->splitToken($tokenString)
			->validateExpiration();
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testSplitTokenFail()
	{
		$tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9';

		$validator = new TokenValidator();

		$validator->splitToken($tokenString);
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testSplitTokenFailNoDot()
	{
		$tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

		$validator = new TokenValidator();

		$validator->splitToken($tokenString);
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testSplitTokenFailFourDot()
	{
		$tokenString = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
			eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
			eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

		$validator = new TokenValidator();

		$validator->splitToken($tokenString);
	}

	/**
	 * @expectedException ReallySimpleJWT\Exception\TokenValidatorException
	 */
	public function testValidateSignatureFail()
	{
		$validator = new TokenValidator();

		$tokenString = Token::getToken(
			734, 
			'ab9OPP10-)9)', 
			Carbon::now()->addMinutes(11)->toDateTimeString(),
			'www.cars.com'
		);

		$tokenString = substr($tokenString, 0, -1);

		$this->assertTrue(
			$validator->splitToken($tokenString)
				->validateExpiration()
				->validateSignature('ab9OPP10-)9)')
		);
	}
}