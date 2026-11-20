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

/**
 * Exposes the protected methods of the filter.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 * @access private
 */
class ezcMvcAuthenticationFilterWrapper extends ezcMvcAuthenticationFilter
{
    public function setupAuth( $user = null, $password = null )
    {
        return parent::setupAuth( $user, $password );
    }

    public function hashPassword( $password )
    {
        return parent::hashPassword( $password );
    }
}

/**
 * A filter which overrides hashPassword() with a deterministic hash.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 * @access private
 */
class ezcMvcAuthenticationFilterSha1Wrapper extends ezcMvcAuthenticationFilter
{
    protected function hashPassword( $password )
    {
        return sha1( (string) $password );
    }
}

/**
 * Base class for the tests of ezcMvcAuthenticationFilter. Sets up a user
 * table in an SQLite database in memory.
 *
 * @package MvcAuthenticationTiein
 * @version //autogen//
 * @subpackage Tests
 * @access private
 */
abstract class ezcMvcAuthenticationFilterTestCase extends ezcTestCase
{
    protected $db;

    public function setUp() : void
    {
        if ( !ezcBaseFeatures::hasExtensionSupport( 'pdo_sqlite' ) )
        {
            $this->markTestSkipped( 'PHP must be compiled with PDO SQLite.' );
        }
        $this->db = ezcDbFactory::create( 'sqlite://:memory:' );
        $this->db->exec( 'CREATE TABLE "user" ( "email" VARCHAR(255) PRIMARY KEY, "name" VARCHAR(255), "password" VARCHAR(255), "full name" VARCHAR(255) )' );
        ezcDbInstance::set( $this->db );
        $_SESSION = array();
    }

    public function tearDown() : void
    {
        $_SESSION = array();
        ezcDbInstance::reset();
    }

    protected function insertUser( $email, $password )
    {
        $s = $this->db->prepare( 'INSERT INTO "user" ( "email", "name", "password" ) VALUES ( ?, ?, ? )' );
        $s->execute( array( $email, 'Jan Modaal', $password ) );
    }

    protected function storedPassword( $email )
    {
        $s = $this->db->prepare( 'SELECT "password" FROM "user" WHERE "email" = ?' );
        $s->execute( array( $email ) );
        return $s->fetchColumn( 0 );
    }

    protected function login( ezcMvcAuthenticationFilter $filter, $user, $password )
    {
        return $filter->login( new ezcMvcRequest(), $user, $password )->run();
    }
}
?>
