<?php

$finder = PhpCsFixer\Finder::create()->in(
    [__DIR__ . '/src', __DIR__ . '/tests']
);

$config = new PhpCsFixer\Config();
return $config->setRules([
        '@PSR12' => true,
        'no_unused_imports' => true,
    ])
    ->setFinder($finder);
