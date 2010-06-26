<?php

/**
 * Tests for the KVForm module.
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

require_once 'Auth/OpenID/KVForm.php';

class Auth_OpenID_KVFormTest extends PHPUnit_Framework_TestCase {

    function kvform_data() {
        return array(
            array(
                'name' => 'simple',
                'str' => "college:harvey mudd\n",
                'arr' => array('college' => 'harvey mudd'),
                'lossy' => 'neither',
                'errors' => 0,
            ),
            array(
                'name' => 'empty',
                'str' => '',
                'arr' => array(),
                'lossy' => 'neither',
                'errors' => 0
            ),
            array(
                'name' => 'empty (just newline)',
                'str' => "\n",
                'arr' => array(),
                'lossy' => 'str',
                'errors' => 1,
            ),
            array(
                'name' => "empty (double newline)",
                'str' => "\n\n",
                'arr' => array(),
                'lossy' => "str",
                'errors' => 2,
            ),
            array(
                'name' => 'empty (no colon)',
                'str' => "East is least\n",
                'arr' => array(),
                'lossy' => 'str',
                'errors' => 1,
            ),
            array(
                'name' => 'two keys',
                'str' => "city:claremont\nstate:CA\n",
                'arr' => array('city' => 'claremont',
                               'state' => 'CA'),
                'lossy' => 'neither',
                'errors' => 0,
            ),
            array(
                'name' => 'real life',
                'str' => "is_valid:true\ninvalidate_handle:{HMAC-SHA1:2398410938412093}\n",
                'arr' => array('is_valid' => 'true',
                               'invalidate_handle' =>
                               '{HMAC-SHA1:2398410938412093}'),
                'lossy' => 'str',
                'errors' => 0,
            ),
            array(
                'name' => 'empty key and value',
                'str' => ":\n",
                'arr' => array(''=>''),
                'lossy' => 'neither',
                'errors' => 0,
            ),
            array(
                'name' => 'empty key, not value',
                'str' => ":missing key\n",
                'arr' => array(''=>'missing key'),
                'lossy' => 'neither',
                'errors' => 0,
            ),
            array(
                'name' => 'whitespace at front of key',
                'str' => " street:foothill blvd\n",
                'arr' => array('street'=>'foothill blvd'),
                'lossy' => 'str',
                'errors' => 1,
            ),
            array(
                'name' => 'whitespace at front of value',
                'str' => "major: computer science\n",
                'arr' => array('major'=>'computer science'),
                'lossy' => 'str',
                'errors' => 1,
            ),
            array(
                'name' => 'whitespace around key and value',
                'str' => " dorm : east \n",
                'arr' => array('dorm'=>'east'),
                'lossy' => 'str',
                'errors' => 2,
            ),
            array(
                'name' => 'missing trailing newline',
                'str' => 'e^(i*pi)+1:0',
                'arr' => array('e^(i*pi)+1'=>'0'),
                'lossy' => 'str',
                'errors' => 1,
            ),
            array(
                'name' => 'missing trailing newline (two key)',
                'str' => "east:west\nnorth:south",
                'arr' => array('east'=>'west',
                               'north'=>'south'),
                'lossy' => 'str',
                'errors' => 1,
            ),
            array(
                'name' => 'array whitespace',
                'str' => " k :v\n",
                'arr' => array(' k ' => 'v'),
                'lossy' => 'both',
                'errors' => 2,
            ),
            array(
                'name' => 'array ordering 1',
                'str' => "a:x\nb:x\nc:x\n",
                'arr' => array('a' => 'x',
                               'b' => 'x',
                               'c' => 'x'),
                'lossy' => 'neither',
                'errors' => 0,
            ),
            array(
                'name' => 'array ordering 2',
                'str' => "a:x\nc:x\nb:x\n",
                'arr' => array('a' => 'x',
                               'c' => 'x',
                               'b' => 'x'),
                'lossy' => 'str',
                'errors' => 0,
            ),
        );
    }

    /**
     * @dataProvider kvform_data
     */
    function test_kvform($name, $str, $arr, $lossy, $errs) {
        // Do one parse, after which arrayToKV and kvToArray should be
        // inverses.
        $parsed1 = Auth_OpenID_KVForm::toArray($str);
        $serial1 = Auth_OpenID_KVForm::fromArray($arr);

        if ($lossy == 'neither' || $lossy == 'str') {
            $this->assertEquals($arr, $parsed1, 'str was lossy');
        }

        if ($lossy == 'neither' || $lossy == 'arr') {
            $this->assertEquals($str, $serial1, 'array was lossy');
        }

        $parsed2 = Auth_OpenID_KVForm::toArray($serial1);
        $serial2 = Auth_OpenID_KVForm::fromArray($parsed1);

        // Round-trip both
        $parsed3 = Auth_OpenID_KVForm::toArray($serial2);
        $serial3 = Auth_OpenID_KVForm::fromArray($parsed2);

        $this->assertEquals($serial2, $serial3, 'serialized forms differ');

        // Check to make sure that they're inverses.
        $this->assertEquals($parsed2, $parsed3, 'parsed forms differ');
    }

    function nullProvider() {
        return array(
            array(
                "name" => "colon in key",
                "arr" => array("k:k" => 'v'),
            ),
            array(
                "name" => "newline in key",
                "arr" => array("k\nk" => 'v'),
            ),
            array(
                "name" => "newline in value",
                "arr" => array('k' => "v\nv"),
            ),
        );
    }

    /**
     * @dataProvider nullProvider
     */
    function test_null($name, $arr) {
        $serialized = Auth_OpenID_KVForm::fromArray($arr);
        $this->assertTrue($serialized === null, 'serialization unexpectedly succeeded');
    }

}

