<?php

namespace Rizeway\Bundle\CasBundle\Security;

use Rizeway\Bundle\CasBundle\Lib\CAS;
use Rizeway\Bundle\CasBundle\Lib\Storage;
use Rizeway\Bundle\CasBundle\Lib\Client;
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
     * @var \Rizeway\Bundle\CasBundle\Lib\Storage
     */
    protected $storage;

    /**
     * @var \Rizeway\Bundle\CasBundle\Lib\Client
     */
    protected $client;

    /**
     * @var string
     */
    protected $checkPath;

    /**
     * @var string
     */
    protected $callbackBaseUrl;

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
     * @var \Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface
     */
    protected $sessionStrategy;


    /**
     * @param SecurityContextInterface $securityContext
     * @param AuthenticationManagerInterface $authenticationManager
     * @param SessionAuthenticationStrategyInterface $sessionStrategy
     * @param HttpUtils $httpUtils
     * @param $providerKey
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param LoggerInterface $logger
     * @param CAS $cas
     * @param Storage $storage
     * @param Client $client
     * @param $callback
     * @param $checkPath
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager,
        SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey,
        AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler,
        LoggerInterface $logger = null, CAS $cas, Storage $storage, Client $client, $callbackBaseUrl, $checkPath)
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
        $this->storage = $storage;
        $this->client = $client;
        $this->callbackBaseUrl = $callbackBaseUrl;
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

            $this->storage->addPgt($request->get('pgtId'), $request->get('pgtIou'));
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
            if ($request->isXmlHttpRequest() && !$request->get('forceRedirect', false)) {
                return new Response('Unauthorized', 401);
            }

            $this->log('CAS authentication : Redirect to CAS Login page');
            return new RedirectResponse($this->cas->getLoginUrl($service));
        }

        $this->log('CAS authentication : Validation Request');
        if ($this->cas->isProxy()) {
            $callback = $this->callbackBaseUrl.$this->checkPath."?callbackProxy=true";
            $validationResult = $this->client->validateServiceTicket($service, $request->get('ticket'), $callback);
        } else {
            $validationResult = $this->client->validateServiceTicket($service, $request->get('ticket'));
        }
        $credentials = array('ROLE_USER');
        $token = new PreAuthenticatedToken($validationResult['user'], $credentials, $this->providerKey);

        if ($this->cas->isProxy()) {
            $token->setAttribute('pgt', $this->storage->getPgt($validationResult['pgtiou']));
        }

        $this->log(sprintf('CAS authentication success: %s', $validationResult['user']));

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

    /**
     * @param $message
     */
    private function log($message)
    {
        if (null !== $this->logger) {
            $this->logger->info($message);
        }
    }
}
