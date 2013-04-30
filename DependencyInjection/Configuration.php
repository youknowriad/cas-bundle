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
                ->scalarNode('server')->defaultFalse()->end()
                ->variableNode('url')->end()
                ->scalarNode('cert')->defaultFalse()->end()
                ->scalarNode('username_attribute')->end()
                ->scalarNode('proxy')->defaultFalse()->end()
                ->scalarNode('callback')->defaultFalse()->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
