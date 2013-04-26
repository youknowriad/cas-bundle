<?php

namespace Rizeway\Bundle\CasBundle\Lib;

class CAS
{

    protected $server;
    protected $port;
    protected $path;
    protected $cert;
    protected $protocol;
    protected $usernameAttribute;
    protected $validationUrl;

    public function __construct($server, $port, $path, $cert, $protocol, $usernameAttribute, $validationUrl)
    {
        $this->server = $server;
        $this->port = $port;
        $this->path = $path;
        $this->cert = $cert;
        $this->protocol = $protocol;
        $this->usernameAttribute = $usernameAttribute;
        $this->validationUrl = $validationUrl;
    }

    public function getCert()
    {
        return $this->cert;
    }

    public function getPath()
    {
        return $this->path;
    }

    public function getPort()
    {
        return $this->port;
    }

    public function getProtocol()
    {
        return $this->protocol;
    }

    public function getServer()
    {
        return $this->server;
    }

    public function getUsernameAttribute()
    {
        return $this->usernameAttribute;
    }

    public function getValidationUrl()
    {
        return $this->validationUrl;
    }
}
