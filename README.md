RIZEWAY CAS Bundle
==================
Cas Authentification in Symfony 2

Installation
---------------

### 1- Add the dependency to your composer.json

    "require": {
        "rizeway/cas-bundle": "0.1.x-dev"
    },

### 2- Add the bundle to your kernel app/AppKernel.php file to update symfony Kernel

        $bundles = array(
            new Rizeway\Bundle\CasBundle\RizewayCasBundle(),
        );

### 3- Parameters Symfony sandbox for use RizewayCasBundle

Edit app/config/config.yml and add the your configuration

    rizeway_cas:
        server: server.com
        port: 443
        path: /cas/
        cert: /my-key.cert
        protocol: '2.0'
        username_attribute: login

### 4- Edit app/config/security.yml file to add your provider and firewall

        providers:
            CAS:
                id: my_user_provider

	    firewalls:
	        dev:
	            pattern:  ^/(_(profiler|wdt)|css|images|js)/
	            security: false
	
	        secured_area:
	            pattern:    ^/demo/secured/
                    cas:
                        check_path: /login/check
                logout:
                    path:   /logout
                    success_handler: cas.security.handler.logout

### 5- Edit app/config/routing.yml file to add empty routes for your login check and logout paths
