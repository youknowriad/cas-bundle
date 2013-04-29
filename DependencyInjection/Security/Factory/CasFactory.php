<?php

namespace Rizeway\Bundle\CasBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;

class CasFactory extends AbstractFactory
{
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);

        $node
            ->children()
                ->scalarNode('check_path')->end()
            ->end()
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function getPosition()
    {
        return 'pre_auth';
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return 'cas';
    }

    /**
     * {@inheritdoc}
     */
    protected function isRememberMeAware($config)
    {  
        return false;
    }

    protected function getListenerId()
    {
        return 'cas.security.authentication.listener';
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {  
        $provider = 'security.authentication.provider.pre_authenticated.'.$id;
        $container
            ->setDefinition($provider, new DefinitionDecorator('security.authentication.provider.pre_authenticated'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->addArgument($id)
        ;

        return $provider;
    }

    protected function createListener($container, $id, $config, $userProvider)
    {
        $listenerId = $this->getListenerId();
        $listener = new DefinitionDecorator($listenerId);
        $listener->replaceArgument(4, $id);
        $listener->replaceArgument(5, new Reference($this->createAuthenticationSuccessHandler($container, $id, $config)));
        $listener->replaceArgument(6, new Reference($this->createAuthenticationFailureHandler($container, $id, $config)));
        $listener->replaceArgument(9, $config['check_path']);

        $listenerId .= '.'.$id;
        $container->setDefinition($listenerId, $listener);

        return $listenerId;
    }

    protected function createEntryPoint($container, $id, $config, $defaultEntryPoint)
    {
        $entryPointId = 'cas.security.authentication.listener.entry_point.'.$id;
        $container
            ->setDefinition($entryPointId, new DefinitionDecorator('cas.security.authentication.cas_entry_point'))
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument($config['check_path'])
            ->addArgument(false)
        ;

        return $entryPointId;
    }
}
