<?php

$finder = PhpCsFixer\Finder::create()->in(
    [__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/benchmarks']
);

$config = new PhpCsFixer\Config();
return $config->setRules([
        '@PSR12' => true,
        'no_unused_imports' => true,
        'declare_strict_types' => true,
        'php_unit_strict' => true,
    ])
    ->setFinder($finder);
