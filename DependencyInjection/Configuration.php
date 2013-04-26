<?php

namespace Rizeway\Bundle\CasBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $treeBuilder->root('rizeway_cas')
            ->children()
                ->scalarNode('server')->end()
                ->variableNode('port')->end()
                ->scalarNode('path')->end()
                ->scalarNode('cert')->end()
                ->scalarNode('protocol')->defaultValue('S1')->end()
                ->scalarNode('username_attribute')->end()
                ->scalarNode('validation_url')->defaultFalse()->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
