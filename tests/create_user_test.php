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
 * Tests ezcMvcAuthenticationFilter::createUser().
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 */
class ezcMvcAuthenticationFilterCreateUserTest extends ezcMvcAuthenticationFilterTestCase
{
    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( __CLASS__ );
    }

    public function testCreateUserQuotesExtraInfoColumns()
    {
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array( 'full name' => 'Jan Modaal' ) );
        $s = $this->db->query( 'SELECT "full name" FROM "user"' );
        $this->assertEquals( 'Jan Modaal', $s->fetchColumn( 0 ) );
    }

    public function testCreateUserExtraInfoColumnWithQuote()
    {
        // the key is one column name, even when it contains the quote character
        $this->db->exec( 'ALTER TABLE "user" ADD COLUMN "na""me" VARCHAR(255)' );
        $filter = new ezcMvcAuthenticationFilter();
        $filter->createUser( 'jan@example.com', 'qwerty', array( 'na"me' => 'Jan Modaal' ) );
        $s = $this->db->query( 'SELECT "na""me", "name" FROM "user"' );
        $this->assertEquals( array( 'Jan Modaal', null ), $s->fetch( PDO::FETCH_NUM ) );
    }
}
?>
