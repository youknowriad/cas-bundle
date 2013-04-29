<?php

namespace Rizeway\Bundle\CasBundle\Security;

use Rizeway\Bundle\CasBundle\Lib\CAS;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;

require_once(dirname(__FILE__) . '/../../../../../../gorg/phpcas/CAS.php');

class LogoutSuccessHandler implements LogoutSuccessHandlerInterface
{
    /**
     * @var \Rizeway\Bundle\CasBundle\Lib\CAS
     */
    protected $cas;

    /**
     * @param CAS $cas
     */
    public function __construct(CAS $cas)
    {
        $this->cas = $cas;
    }

    public function onLogoutSuccess(Request $request)
    {
        return new RedirectResponse($this->cas->getLogoutUrl());
    }
}
