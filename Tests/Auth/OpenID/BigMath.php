<?php
/**
 * Tests for the BigMath functions.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005-2008 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

require_once 'Auth/OpenID/BigMath.php';
require_once 'Tests/Auth/OpenID/TestUtil.php';


class Auth_OpenID_BigMathTest extends PHPUnit_Framework_TestCase {

    protected function setUp() {
        if (defined('Auth_OpenID_NO_MATH_SUPPORT') && Auth_OpenID_NO_MATH_SUPPORT) {
            $this->markTestSkipped('Auth_OpenID_NO_MATH_SUPPORT is set');
        }
    }

    /**
     * Computes the maximum integer value for this PHP installation.
     *
     * @return int $max_int_value The maximum integer value for this
     * PHP installation
     */
    static function maxint() {
        /* assumes largest integer is of form 2^n - 1 */
        $to_test = pow(2, 16);
        while (1) {
            $last = $to_test;
            $to_test = 2 * $to_test;
            if (($to_test < $last) || (!is_int($to_test))) {
                return($last + ($last - 1));
            }
        }
    }

    function binLongConvertRnd_dataProvider() {
        $data = array();

        $count = (defined('Tests_Auth_OpenID_thorough') && Tests_Auth_OpenID_thorough) ? 500 : 4;
        for($i=0; $i<$count; $i++) {
            $data[] = array();
        }

        return $data;
    }

    /**
     * @dataProvider binLongConvertRnd_dataProvider
     */
    function test_binLongConvertRnd() {
        $lib = Auth_OpenID_getMathLib();
        $max = self::maxint();

        $n = $lib->init(0);
        foreach (range(0, 9) as $i) {
            $rnd = $lib->rand($max);
            $n = $lib->add($n, $rnd);
        }
        $s = $lib->longToBinary($n);
        $this->assertTrue(is_string($s));
        $n_prime = $lib->binaryToLong($s);
        $this->assertEquals($lib->cmp($n, $n_prime), 0);
    }

    function binLongConvert_dataProvider() {
        return array(
            array("\x00", 0),
            array("\x01", 1),
            array("\x7F", 127),
            array("\x00\x80", 128),
            array("\x00\x81", 129),
            array("\x00\xFF", 255),
            array("\x00\x80\x00", 32768),
            array("OpenID is cool", "1611215304203901150134421257416556")
        );
    }

    /**
     * @dataProvider binLongConvert_dataProvider
     */
    function test_binLongConvert($bin, $lng_m) {
        $lib = Auth_OpenID_getMathLib();
        $lng = $lib->init($lng_m);

        $n_prime = $lib->binaryToLong($bin);
        $s_prime = $lib->longToBinary($lng);
        $this->assertEquals($lib->cmp($lng, $n_prime), 0);
        $this->assertTrue($bin == $s_prime);
    }

    function test_rand() {
        $lib = Auth_OpenID_getMathLib();
        $stop = $lib->pow(2, 128);
        $a = $lib->rand($stop);
        $b = $lib->rand($stop);

        $this->assertFalse($lib->cmp($b, $a) == 0, "Same: $a $b");

        $n = $lib->init(self::maxint());
        $n = $lib->add($n, 1);

        // Make sure that we can generate random numbers that are
        // larger than platform int size
        $result = $lib->rand($n);

        // What can we say about the result?
    }

    function base64Convert_dataProvider() {
        $lib = Auth_OpenID_getMathLib();

        $lines = file('Tests/Auth/OpenID/data/n2b64');
        $count = (defined('Tests_Auth_OpenID_thorough') && Tests_Auth_OpenID_thorough) ? count($lines) : 4;

        $data = array();
        foreach ($lines as $line) {
            if ($count-- <= 0) break;

            $line = trim($line);
            list($b64, $ascii) = explode(' ', $line);
            $long = $lib->init($ascii);
            $data[] = array($b64, $long);
        }

        return $data;
    }

    /**
     * @dataProvider base64Convert_dataProvider
     */
    function test_base64Convert($b64, $num) {
        $lib = Auth_OpenID_getMathLib();

        // base64 -> long
        $actual_long = $lib->base64ToLong($b64);
        $this->assertTrue($lib->cmp($num, $actual_long) == 0);

        // long -> base64
        $actual_b64 = $lib->longToBase64($num);
        $this->assertEquals($b64, $actual_b64);
    }

}

