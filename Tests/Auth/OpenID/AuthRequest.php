<?php

require_once 'Tests/Auth/OpenID/TestCase.php';
require_once "Tests/Auth/OpenID/TestSuite.php";

require_once 'Auth/OpenID/Association.php';
require_once 'Auth/OpenID/Consumer.php';


class Auth_OpenID_AuthRequestSuite extends Auth_OpenID_TestSuite {
    public static function suite() {
        $suite = new Auth_OpenID_AuthRequestSuite();

        $suite->addTestSuite('Auth_OpenID_OpenID2AuthRequestTest');
        $suite->addTestSuite('Auth_OpenID_OpenID1AuthRequestTest');
        $suite->addTestSuite('Auth_OpenID_OpenID2ImmediateAuthRequestTest');
        $suite->addTestSuite('Auth_OpenID_OpenID1ImmediateAuthRequestTest');

        return $suite;
    }
}


abstract class Auth_OpenID_AuthRequestTestCase extends Auth_OpenID_TestCase {

    var $preferred_namespace = null;
    var $immediate = false;
    var $expected_mode = 'checkid_setup';

    function setUp() {
        $this->endpoint = new AuthRequest_DummyEndpoint();
        $this->endpoint->local_id = 'http://server.unittest/joe';
        $this->endpoint->claimed_id = 'http://joe.vanity.example/';
        $this->endpoint->server_url = 'http://server.unittest/';
        $this->endpoint->preferred_namespace = $this->preferred_namespace;
        $this->realm = 'http://example/';
        $this->return_to = 'http://example/return/';
        $this->assoc = (object) array('handle' => 'assoc-handle');
        $this->authreq = new Auth_OpenID_AuthRequest($this->endpoint, $this->assoc);
    }

    function assertAnonymous($message) {
        foreach (array('claimed_id', 'identity') as $key) {
            $this->assertOpenIDNotHasKey($message, $key);
        }
    }

    function assertHasRequiredFields($message)
    {
        $this->assertEquals($this->preferred_namespace, $this->authreq->message->getOpenIDNamespace());
        $this->assertEquals($this->preferred_namespace, $message->getOpenIDNamespace());
        $this->assertOpenIDValueEquals($message, 'mode', $this->expected_mode);

        // Implement these in subclasses because they depend on protocol differences!
        $this->assertHasRealm($message);
        $this->assertIdentifiersPresent($message);
    }

    abstract function assertHasRealm($message);

    abstract function assertIdentifiersPresent($message);

    // TESTS

    function test_checkNoAssocHandle()
    {
        $this->authreq->assoc = null;
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                          $this->immediate);

        $this->assertOpenIDNotHasKey($msg, 'assoc_handle');
    }

    function test_checkWithAssocHandle()
    {
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                         $this->immediate);

        $this->assertOpenIDValueEquals($msg, 'assoc_handle',
                                           $this->assoc->handle);
    }

    function test_addExtensionArg()
    {
        $this->authreq->addExtensionArg('bag:', 'color', 'brown');
        $this->authreq->addExtensionArg('bag:', 'material', 'paper');
        $this->assertTrue($this->authreq->message->namespaces->contains('bag:'));
        $this->assertEquals($this->authreq->message->getArgs('bag:'),
                            array('color' => 'brown',
                                  'material' => 'paper'));
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                          $this->immediate);

        // XXX: this depends on the way that Message assigns
        // namespaces. Really it doesn't care that it has alias "0",
        // but that is tested anyway
        $post_args = $msg->toPostArgs();
        $this->assertEquals('brown', $post_args['openid.ext0.color']);
        $this->assertEquals('paper', $post_args['openid.ext0.material']);
    }

    function test_standard()
    {
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                         $this->immediate);

        $this->assertHasIdentifiers(
             $msg, $this->endpoint->local_id,
             $this->endpoint->claimed_id);
    }
}


class AuthRequest_DummyEndpoint {
    var $preferred_namespace = null;
    var $local_id = null;
    var $server_url = null;
    var $is_op_identifier = false;

    function preferredNamespace() {
        return $this->preferred_namespace;
    }

    function getLocalID() {
        return $this->local_id;
    }

    function isOPIdentifier() {
        return $this->is_op_identifier;
    }
}


class Auth_OpenID_OpenID2AuthRequestTest extends Auth_OpenID_AuthRequestTestCase {
    var $preferred_namespace = Auth_OpenID_OPENID2_NS;

    function assertHasRealm($msg)
    {
        // check presence of proper realm key and absence of the wrong one.
        $this->assertOpenIDValueEquals($msg, 'realm', $this->realm);
        $this->assertOpenIDNotHasKey($msg, 'trust_root');
    }

    function assertIdentifiersPresent($msg)
    {
        $identity_present = $msg->hasKey(Auth_OpenID_OPENID_NS, 'identity');
        $claimed_present = $msg->hasKey(Auth_OpenID_OPENID_NS, 'claimed_id');

        $this->assertEquals($claimed_present, $identity_present);
    }

    function assertHasIdentifiers($msg, $op_specific_id, $claimed_id)
    {
        $this->assertOpenIDValueEquals($msg, 'identity', $op_specific_id);
        $this->assertOpenIDValueEquals($msg, 'claimed_id', $claimed_id);
    }

    // TESTS

    function test_markup_checkidImmediate()
    {
        $result = $this->authreq->formMarkup($this->realm,
                                             null, true);
        $this->assertTrue(Auth_OpenID::isFailure($result));
    }

    function test_markup_returnToArgs()
    {
        $this->authreq->return_to_args = array('extra' => 'args');
        $result = $this->authreq->formMarkup($this->realm,
                                             null, false);
        $this->assertTrue(Auth_OpenID::isFailure($result));
    }

    function test_setAnonymousWorksForOpenID2()
    {
        // OpenID AuthRequests should be able to set 'anonymous' to true.
        $this->assertTrue($this->authreq->message->isOpenID2());
        $this->assertTrue($this->authreq->setAnonymous(true));
        $this->assertTrue($this->authreq->setAnonymous(false));
    }

    function test_userAnonymousIgnoresIdentfier()
    {
        $this->authreq->setAnonymous(true);
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                          $this->immediate);
        $this->assertHasRequiredFields($msg);
        $this->assertAnonymous($msg);
    }

    function test_opAnonymousIgnoresIdentifier()
    {
        $this->endpoint->is_op_identifier = true;
        $this->authreq->setAnonymous(true);
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                          $this->immediate);
        $this->assertHasRequiredFields($msg);
        $this->assertAnonymous($msg);
    }

    function test_opIdentifierSendsIdentifierSelect()
    {
        $this->endpoint->is_op_identifier = true;
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                          $this->immediate);
        $this->assertHasRequiredFields($msg);
        $this->assertHasIdentifiers($msg,
                                        Auth_OpenID_IDENTIFIER_SELECT,
                                        Auth_OpenID_IDENTIFIER_SELECT);
    }
}

class Auth_OpenID_OpenID1AuthRequestTest extends Auth_OpenID_AuthRequestTestCase {
    var $preferred_namespace = Auth_OpenID_OPENID1_NS;

    function setUpEndpoint()
    {
        parent::setUpEndpoint();
        $this->endpoint->preferred_namespace = Auth_OpenID_OPENID1_NS;
    }

    function assertHasIdentifiers($msg, $op_specific_id, $claimed_id)
    {
        // Make sure claimed_is is *absent* in request.
        $this->assertOpenIDValueEquals($msg, 'identity', $op_specific_id);
        $this->assertOpenIDNotHasKey($msg, 'claimed_id');
    }

    function assertIdentifiersPresent($msg)
    {
        $this->assertOpenIDNotHasKey($msg, 'claimed_id');
        $this->assertTrue($msg->hasKey(Auth_OpenID_OPENID_NS, 'identity'));
    }

    function assertHasRealm($msg)
    {
        // check presence of proper realm key and absence of the wrong one.
        $this->assertOpenIDValueEquals($msg, 'trust_root', $this->realm);
        $this->assertOpenIDNotHasKey($msg, 'realm');
    }

    // TESTS

    function test_markup_missingReturnTo()
    {
        $result = $this->authreq->formMarkup($this->realm,
                                             null, false);
        $this->assertTrue(Auth_OpenID::isFailure($result));
    }

    function test_setAnonymousFailsForOpenID1()
    {
        // OpenID 1 requests MUST NOT be able to set anonymous to True
        $this->assertTrue($this->authreq->message->isOpenID1());
        $this->assertFalse($this->authreq->setAnonymous(true));
        $this->assertTrue($this->authreq->setAnonymous(false));
    }

    function test_identifierSelect()
    {
        // Identfier select SHOULD NOT be sent, but this pathway is in
        // here in case some special discovery stuff is done to
        // trigger it with OpenID 1. If it is triggered, it will send
        // identifier_select just like OpenID 2.
        $this->endpoint->is_op_identifier = true;
        $msg = $this->authreq->getMessage($this->realm, $this->return_to,
                                          $this->immediate);
        $this->assertHasRequiredFields($msg);
        $this->assertEquals(Auth_OpenID_IDENTIFIER_SELECT,
                            $msg->getArg(Auth_OpenID_OPENID1_NS,
                                         'identity'));
    }
}

class Auth_OpenID_OpenID1ImmediateAuthRequestTest extends Auth_OpenID_OpenID1AuthRequestTest {
    var $immediate = true;
    var $expected_mode = 'checkid_immediate';
}

class Auth_OpenID_OpenID2ImmediateAuthRequestTest extends Auth_OpenID_OpenID2AuthRequestTest {
    var $immediate = true;
    var $expected_mode = 'checkid_immediate';
}

