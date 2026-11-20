<?php
/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache License, Version 2.0
 * @filesource
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */

require_once( dirname( __FILE__ ) . '/filter_test_case.php' );

/**
 * Tests ezcMvcAuthenticationFilter with a user from the session.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */
class ezcMvcAuthenticationFilterSessionTest extends ezcMvcAuthenticationFilterTestCase
{
    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( __CLASS__ );
    }

    public function testSetupAuthFromSession()
    {
        $filter = new ezcMvcAuthenticationFilterWrapper();
        $_SESSION['ezcAuth_id'] = 'jan@example.com';
        $_SESSION['ezcAuth_timestamp'] = time();

        $deprecations = array();
        // only deprecations from this component count; autoloading a
        // dependency may raise its own
        $src = dirname( __DIR__ ) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR;
        set_error_handler( function ( $errno, $errstr, $errfile ) use ( &$deprecations, $src )
        {
            if ( strncmp( $errfile, $src, strlen( $src ) ) === 0 )
            {
                $deprecations[] = $errstr;
            }
            return true;
        }, E_DEPRECATED );
        try
        {
            $authentication = $filter->setupAuth();
        }
        finally
        {
            restore_error_handler();
        }

        $this->assertEquals( array(), $deprecations );
        $this->assertNull( $authentication->credentials->password );
        $this->assertTrue( $authentication->run() );
    }
}
?>
