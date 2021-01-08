<?php

namespace Tests\Unit\Helper;

use PHPUnit\Framework\TestCase;
use ReallySimpleJWT\Helper\Base64;

class Base64Test extends TestCase
{
    use Base64;

    public function testToBase64Url(): void
    {
        $this->assertSame('hello-_', $this->toBase64Url('he=llo+/'));
    }

    public function testToBase64UrlTwo(): void
    {
        $this->assertSame('_Wor-_12-_', $this->toBase64Url('/Wo==r+/12+/='));
    }

    public function testToBase64(): void
    {
        $this->assertSame('QFDvv71ZLO+/ve+/vVF777', $this->toBase64('QFDvv71ZLO-_ve-_vVF777'));
    }

    public function testAddPadding(): void
    {
        $result = $this->addPadding(
            'QFDvv71ZLO-_ve-_vVF777-92I10XO-_ve-_ve-_vRnvv73vv70r77-9bQQDTzvvv73vv73vv704Ww'
        );

        $this->assertSame(
            'QFDvv71ZLO-_ve-_vVF777-92I10XO-_ve-_ve-_vRnvv73vv70r77-9bQQDTzvvv73vv73vv704Ww==',
            $result
        );
    }
}
