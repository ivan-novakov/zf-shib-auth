<?php


/**
 * Shibboleth authentication adapter for the Zend Framework.
 * 
 * Configuration options:
 * - attrPrefix (string, default '') - apply prefix when retrieving Shibboleth attributes
 * - attrValueSeparator (string, default ';') - value separator for multi-value attributes
 * - sessionIdVar (string, default 'Shib-Session-ID') - env value - containing the Shibboleth session
 * - idpVar (string, default 'Shib-Identity-Provider') - env value - the entity ID of the IdP
 * - appIdVar (string, default 'Shib-Application-ID') - env value - the application ID as configured in shibboleth2.xml
 * - authInstantVar (string, default 'Shib-Authentication-Instant') - env value - the time of authentication
 * - authContextVar (string, default 'Shib-AuthnContext-Decl') - env value - authentication context at the IdP
 * - identityVar (string, default 'uid') - the name of the mapped user attribute containing the user identity
 * - systemVarsInResult (boolean, default true) - true to add env var to the returned user attributes upon successful
 * authentication
 * - attrMap (array, default - see code) - array, that maps Shibboleth attribute names into internal variable names
 * 
 * Usage:
 * ---------------------------------
 * $auth = Zend_Auth::getInstance();
 *
 * $authAdapter = new Zext_Auth_Adapter_Shibboleth(array(
 *   'identityVar' => 'id',
 *   'attrMap' => array(
 *       'uid' => 'id',
 *       'cn' => 'name',
 *       'mail' => 'email'
 *   )
 * ));
 *
 * $result = $auth->authenticate($authAdapter);
 * ---------------------------------
 * 
 * 
 * @author Ivan Novakov <ivan.novakov@debug.cz>
 * @license http://debug.cz/license/freebsd    FreeBSD License
 */
class Zext_Auth_Adapter_Shibboleth implements Zend_Auth_Adapter_Interface
{

    /**
     * The configuration object.
     * 
     * @var Zend_Config
     */
    protected $_config = NULL;

    /**
     * Array of default options.
     * 
     * @var array
     */
    protected $_defaultOptions = array(
        'attrPrefix' => '', 
        'attrValueSeparator' => ';', 
        'sessionIdVar' => 'Shib-Session-ID', 
        'idpVar' => 'Shib-Identity-Provider', 
        'appIdVar' => 'Shib-Application-ID', 
        'authInstantVar' => 'Shib-Authentication-Instant', 
        'authContextVar' => 'Shib-AuthnContext-Decl', 
        'identityVar' => 'uid', 
        'systemVarsInResult' => true, 
        'attrMap' => array(
            'eppn' => 'uid', 
            'cn' => 'cn', 
            'mail' => 'email'
        )
    );

    /**
     * System variable keys.
     * 
     * @var array
     */
    protected $_systemVars = array(
        'idpVar', 
        'appIdpVar', 
        'authIdVar', 
        'authInstantVar', 
        'authContextVar'
    );

    /**
     * Array containing environment variables.
     * 
     * @var array
     */
    protected $_env = array();


    /**
     * Constructor.
     * 
     * @param array $config
     * @param array $env
     */
    public function __construct (Array $config = array(), Array $env = NULL)
    {
        $this->_config = new Zend_Config($config + $this->_defaultOptions);
        
        if (! $env) {
            $env = $_SERVER;
        }
        $this->_env = $env;
    }


    /**
     * Implementation of the authenticate() call defineed by the adapter interface.
     * 
     * @see Zend_Auth_Adapter_Interface::authenticate()
     */
    public function authenticate ()
    {
        /*
         * If there is no Shibboleth session, the authentication is impossible.
         */
        if (! $this->_isSession()) {
            return $this->_failureResult(array(
                'no_session'
            ));
        }
        
        /*
         * Get attributes from the Shibboleth session.
         */
        $userAttrs = $this->_extractAttributes();
        
        /*
         * Check if the "identityVar" is present. If not, the authentication cannot be completed.
         */
        if (! isset($userAttrs[$this->_config->identityVar])) {
            return $this->_failureResult(array(
                'no_identity'
            ), Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND);
        }
        
        /*
         * If the "identityVar" variable contians more than one value, throw an error.
         */
        if (is_array($userAttrs[$this->_config->identityVar])) {
            return $this->_failureResult(array(
                'multiple_id_attr_value'
            ), Zend_Auth_Result::FAILURE_IDENTITY_AMBIGUOUS);
        }
        
        return $this->_successResult($userAttrs);
    }


    /**
     * Returns a failure Zend_Auth_Result.
     * 
     * @param array $messages
     * @param integer $code
     * @return Zend_Auth_Result
     */
    protected function _failureResult (Array $messages, $code = Zend_Auth_Result::FAILURE)
    {
        return new Zend_Auth_Result($code, NULL, $messages);
    }


    /**
     * Returns a successful Zend_Auth_Result.
     * 
     * @param array $userAttrs
     * @return Zend_Auth_Result
     */
    protected function _successResult (Array $userAttrs)
    {
        return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $userAttrs);
    }


    /**
     * Parses Shibboleth attributes and maps them into an array.
     * 
     * @return array
     */
    protected function _extractAttributes ()
    {
        $attrs = array();
        
        /*
         * Use the "attrMap" configuration parameter to map attributes.
         */
        foreach ($this->_config->attrMap->toArray() as $srcIndex => $dstIndex) {
            if ($value = $this->_getEnv($srcIndex)) {
                /*
                 * Some Shibboleth attributes have multiple values, serialized.
                 * The only way to find that out is to try to split the values by separator.
                 */
                $values = explode($this->_config->attrValueSeparator, $value);
                if (count($values) > 1) {
                    $attrs[$dstIndex] = $values;
                } else {
                    $attrs[$dstIndex] = $value;
                }
            }
        }
        
        /*
         * Add relevant environment variables to the array.
         */
        if ($this->_config->systemVarsInResult) {
            foreach ($this->_systemVars as $systemVarName) {
                $envVarName = $this->_config->get($systemVarName);
                if ($envVarName && ($value = $this->_getEnv($envVarName))) {
                    $attrs['env'][$envVarName] = $value;
                }
            }
        }
        
        return $attrs;
    }


    /**
     * Returns true, if a Shibboleth session exists.
     * 
     * @return boolean
     */
    protected function _isSession ()
    {
        return ($this->_getSession());
    }


    /**
     * Returns the Shibboleth session ID, if present. Otherwise returns NULL.
     * 
     * @return string|NULL
     */
    protected function _getSession ()
    {
        return $this->_getEnv($this->_config->sessionIdVar);
    }


    /**
     * Returns the corresponding environment variable value.
     * 
     * @param string $index
     * @return string|NULL
     */
    protected function _getEnv ($index)
    {
        $index = $this->_config->attrPrefix . $index;
        
        if (isset($this->_env[$index])) {
            return $this->_env[$index];
        }
        
        return NULL;
    }
}