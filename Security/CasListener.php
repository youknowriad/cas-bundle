<?php

namespace Rizeway\Bundle\CasBundle\Security;

use Rizeway\Bundle\CasBundle\Lib\CAS;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;

require_once(dirname(__FILE__) . '/../../../../../../../gorg/phpcas/CAS.php');

class CasListener extends AbstractAuthenticationListener
{
    /**
     * @var \Rizeway\Bundle\CasBundle\Lib\CAS
     */
    protected $cas;

    /**
     * {@inheritdoc}
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CAS $cas)
    {
        $this->cas = $cas;

        parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, $options, $logger, $dispatcher);
    }

    /**
     * {@inheritdoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        \phpCAS::client($this->cas->getProtocol(), $this->cas->getServer(), $this->cas->getPort(), $this->cas->getPath(), false);

        if ($this->cas->getValidationUrl()) {
            \phpCAS::setServerServiceValidateURL($this->cas->getValidationUrl());
        }

        if($this->cas->getCert())
        {
            \phpCAS::setCasServerCACert($this->cas->getCert());
        } else {
            \phpCAS::setNoCasServerValidation();
        }
        \phpCAS::forceAuthentication();
        $attributes = \phpCAS::getAttributes();
        $user = $attributes[$this->cas->getUsernameAttribute()];
        $credentials = array('ROLE_USER');

        if (null !== $this->logger) {
            $this->logger->info(sprintf('CAS authentication success: %s', $user));
        }

        return $this->authenticationManager->authenticate(new PreAuthenticatedToken($user, $credentials, $this->providerKey));
    }
}
