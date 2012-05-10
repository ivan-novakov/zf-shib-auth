Shibboleth Authentication for the Zend Framework
================================================

* implements Zend_Auth_Adapter_Interface
* flexible configuration
* "fake" Shibboleth authentication adapter included

Usage:

    $auth = Zend_Auth::getInstance();
    $authAdapter = new ShibbolethAdapter(array(
        'identityVar' => 'id', 
        'attrMap' => array(
            'uid' => 'id', 
            'cn' => 'name',
            'mail' => 'email'
        )
    ));
    $result = $auth->authenticate($authAdapter);


See the source comments for more info about the available options.

More info:
* [Shibboleth](http://shibboleth.net/)
* [Zend Framework](http://framework.zend.com/)