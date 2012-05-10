<?php


/**
 * A special "fake" shibboleth authentication adapter.
 * 
 * Often, Shibboleth environment is not available during application development. This class allows testing
 * authentication without having Shibboleth set up. 
 * 
 * Configuration options:
 * - fail (boolean, default true) - if authentication should fail or not 
 * - failCode (integer, default Zend_Auth_Result::FAILURE) - if fail=true, which Zend_Auth_Result failure code to use
 * - failMessage (string) - if fail=true, what error message to return
 * - userAttrs (array) - array of user attributes to return upon "successful" authentication
 * 
 * @author Ivan Novakov <ivan.novakov@debug.cz>
 * @license http://debug.cz/license/freebsd    FreeBSD License
 */
class Zext_Auth_Adapter_FakeShibboleth implements Zend_Auth_Adapter_Interface
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
        
        'fail' => false, 
        'failCode' => Zend_Auth_Result::FAILURE, 
        'failMessage' => 'auth error', 
        
        'userAttrs' => array(
            'uid' => 'tester', 
            'cn' => 'Test User', 
            'email' => 'test@example.com'
        )
    );


    /**
     * Constructor.
     * 
     * @param array $config
     * @param array $env
     */
    public function __construct (Array $config = array(), Array $env = NULL)
    {
        $this->_config = new Zend_Config($config + $this->_defaultOptions);
    }


    /**
     * @see Zend_Auth_Adapter_Interface::authenticate()
     */
    public function authenticate ()
    {
        if ($this->_config->fail) {
            return new Zend_Auth_Result($this->_config->failCode, NULL, array(
                $this->_config->failMessage
            ));
        }
        
        return new Zend_Auth_Result(Zend_Auth_Result::SUCCESS, $this->_config->userAttrs->toArray());
    }
}