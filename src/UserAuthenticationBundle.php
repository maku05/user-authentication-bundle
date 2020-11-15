<?php


namespace Maku05\UserAuthenticationBundle;


use Maku05\UserAuthenticationBundle\DependencyInjection\UserAuthenticationExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class UserAuthenticationBundle extends Bundle
{
    public function getContainerExtension()
    {
        return new UserAuthenticationExtension();
    }
}