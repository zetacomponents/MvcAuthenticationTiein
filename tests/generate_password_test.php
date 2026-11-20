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
 * Tests ezcMvcAuthenticationFilter::generatePassword().
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */
class ezcMvcAuthenticationFilterGeneratePasswordTest extends ezcMvcAuthenticationFilterTestCase
{
    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( __CLASS__ );
    }

    public function testGeneratePassword()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $passwords = array();
        for ( $i = 0; $i < 20; $i++ )
        {
            $password = $filter->generatePassword( 'jan@example.com' );
            $this->assertMatchesRegularExpression( '/^[a-z0-9]{12}$/', $password );
            $passwords[] = $password;
        }
        $this->assertCount( 20, array_unique( $passwords ) );
    }
}
?>
