<?php

namespace Rizeway\Bundle\CasBundle\Security;

use Guzzle\Service\Client;
use Rizeway\Bundle\CasBundle\Lib\CAS;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\SessionUnavailableException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;

class CasListener implements ListenerInterface
{
    /**
     * @var \Rizeway\Bundle\CasBundle\Lib\CAS
     */
    protected $cas;

    /**
     * @var \Symfony\Component\Security\Core\SecurityContextInterface
     */
    protected $securityContext;

    /**
     * @var \Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var \Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface
     */
    protected $failureHandler;

    /**
     * @var \Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface
     */
    protected $successHandler;

    /**
     * @var \Symfony\Component\Security\Http\HttpUtils
     */
    protected $httpUtils;

    /**
     * @var string
     */
    protected $checkPath;

    /**
     * @var \Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface
     */
    protected $sessionStrategy;

    /**
     * @param SecurityContextInterface $securityContext
     * @param AuthenticationManagerInterface $authenticationManager
     * @param HttpUtils $httpUtils
     * @param LoggerInterface $logger
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param SessionAuthenticationStrategyInterface $sessionStrategy
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param $providerKey
     * @param CAS $cas
     * @param $checkPath
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager,
        SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey,
        AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler,
        LoggerInterface $logger = null, CAS $cas, $checkPath)
    {
        $this->cas = $cas;
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->logger = $logger;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->checkPath = $checkPath;
        $this->httpUtils = $httpUtils;
        $this->sessionStrategy = $sessionStrategy;
        $this->providerKey = $providerKey;
    }

    /**
     * @param GetResponseEvent $event
     * @throws \RuntimeException
     * @throws \Symfony\Component\Security\Core\Exception\SessionUnavailableException
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if (!$this->requiresAuthentication($request)) {
            return;
        }

        if ($this->cas->isProxy() && !$request->get('pgtIou') && $request->get('callbackProxy')) {
            $this->log('CAS authentication : Server Callback Check');
            $response = new Response("done", 200, array('Content-Length' => '4'));
            $event->setResponse($response);
            return;
        } elseif ($this->cas->isProxy() && $request->get('pgtIou')) {
            $this->log('CAS authentication : Server Callback PGTIou '.$request->get('pgtIou'));
            $response = new Response("done", 200, array('Content-Length' => '4'));
            $event->setResponse($response);
            return;
        }

        if (!$request->hasSession()) {
            throw new \RuntimeException('This authentication method requires a session.');
        }

        try {
            if (!$request->hasPreviousSession()) {
                throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
            }

            if (null === $returnValue = $this->attemptAuthentication($request)) {
                return;
            }

            if ($returnValue instanceOf Response) {
                $response = $returnValue;
            } else {
                $this->sessionStrategy->onAuthentication($request, $returnValue);
                $response = $this->onSuccess($request, $returnValue);
            }

        } catch (AuthenticationException $e) {
            $response = $this->onFailure($request, $e);
        }

        $event->setResponse($response);
    }

    /**
     * @param Request $request
     * @return bool
     */
    protected function requiresAuthentication(Request $request)
    {
        return $this->httpUtils->checkRequestPath($request, $this->checkPath);
    }

    /**
     * @param Request $request
     * @return RedirectResponse
     * @throws \Exception
     */
    protected function attemptAuthentication(Request $request)
    {
        $service = $this->httpUtils->generateUri($request, $this->checkPath);

        // Redirect To Login
        if (!$request->get('ticket', false)) {
            $this->log('CAS authentication : Redirect to CAS Login page');
            return new RedirectResponse($this->cas->getLoginUrl($service));
        }

        $this->log('CAS authentication : Validation Request');
        // Ticket Got, Validate the ticket
        if ($cert = $this->cas->getCert()) {
            $options = array(
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_SSL_VERIFYPEER => 1,
                CURLOPT_RETURNTRANSFER => 1,
                CURLOPT_CAINFO => $this->cas->getCert()
            );
        } else {
            $options = array(
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_SSL_VERIFYPEER => 0,
                CURLOPT_RETURNTRANSFER => 1
            );
        }

        if (!$this->cas->isProxy()) {
            $curl = curl_init($this->cas->getValidationUrl($service, $request->get('ticket')));
        } else {
            $callback = "https://localhost:443/vagrant/app_dev.php".$this->checkPath."?callbackProxy=true";
            $curl = curl_init($this->cas->getProxyValidationUrl($service, $request->get('ticket'), $callback));
        }
        curl_setopt_array($curl, $options);

        $curlResponse = curl_exec($curl);
        if (!$curlResponse) {
            throw new \Exception("Error in CAS Validation Request : ". curl_error($curl));
        }

        $document = new \DOMDocument();
        $document->loadXML($curlResponse);
        $attributes = $document->getElementsByTagName('attributes');
        if (!$attributes->length) {
            throw new \Exception("Invalid CAS Validation Response");
        }

        $this->log('CAS authentication : Parsing Validation Response');
        $user = $document->getElementsByTagName($this->cas->getUsernameAttribute())->item(0)->textContent;
        $credentials = array('ROLE_USER');
        $token = new PreAuthenticatedToken($user, $credentials, $this->providerKey);
        if ($this->cas->isProxy()) {
            if (!$document->getElementsByTagName('proxyGrantingTicket')->length) {
                throw new \Exception("No proxy ticket found in validation request");
            }
            $token->setAttribute('pgt', $document->getElementsByTagName('proxyGrantingTicket')->item(0)->textContent);
        }

        $this->log(sprintf('CAS authentication success: %s', $user));

        return $this->authenticationManager->authenticate($token);
    }


    private function onFailure(Request $request, AuthenticationException $failed)
    {
        $this->logger->info(sprintf('Authentication request failed: %s', $failed->getMessage()));
        $this->securityContext->setToken(null);

        $response = $this->failureHandler->onAuthenticationFailure($request, $failed);

        if (!$response instanceof Response) {
            throw new \RuntimeException('Authentication Failure Handler did not return a Response.');
        }

        return $response;
    }

    private function onSuccess(Request $request, TokenInterface $token)
    {
        $this->logger->info(sprintf('User "%s" has been authenticated successfully', $token->getUsername()));
        $this->securityContext->setToken($token);
        $session = $request->getSession();
        $session->remove(SecurityContextInterface::AUTHENTICATION_ERROR);
        $session->remove(SecurityContextInterface::LAST_USERNAME);
        $response = $this->successHandler->onAuthenticationSuccess($request, $token);

        if (!$response instanceof Response) {
            throw new \RuntimeException('Authentication Success Handler did not return a Response.');
        }

        return $response;
    }

    private function log($message)
    {
        if (null !== $this->logger) {
            $this->logger->info($message);
        }
    }
}
