Awesome Security Checklist [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
===============

Sharing, suggestions and contributions are always welcome! Please take a look at the [contribution guidelines and quality standard](https://github.com/mostafahussein/awesome-security-checklist/blob/master/CONTRIBUTING.md) first.

Thanks to all [contributors](https://github.com/mostafahussein/awesome-security-checklist/graphs/contributors), you're awesome and this wouldn't be possible without you!

## Table of Contents

- [Web Applications](#web-applications)
    * Basic Security Checklist
    * Wordpress Security Checklist
    * NodeJS Security Checklist
    * Ruby on Rails Security Checklist

## Web Applications
* Basic Security Checklist - Mirror for [securitychecklist.org](https://securitychecklist.org). A set of clear TODO's for hosting secure sites, featuring TLS, strong ciphers, security headers, fail2ban, SSH configs, etc..
  * [x] Is the website only served over https?
  ```bash
  Test:
      $ curl -s -I http://example.org | grep '^HTTP'
      HTTP/1.1 301 Moved Permanently
      $ curl -s -I https://example.org | grep '^HTTP'
      HTTP/1.1 200 OK
  ```
  * [x] Is the HSTS http-header set?
  ```bash
  Test:
      $ curl -s -I https://example.org | grep '^Strict'
      Strict-Transport-Security: max-age=63072000; includeSubdomains;
  ```
  * [x] Is the server certificate at least 4096 bits?
  ```bash
  Test:
      $ openssl s_client -showcerts -connect example.org:443 |& grep '^Server public key'
      Server public key is 4096 bit
  ```
  * [x] Is TLS1.2 the only supported protocol?
  ```bash
  Test:
      $ curl --sslv3 https://example.org
      curl: (35) Server aborted the SSL handshake
      $ curl --tlsv1.0 -I https://example.org
      curl: (35) Server aborted the SSL handshake
      $ curl --tlsv1.1 -I https://example.org
      curl: (35) Server aborted the SSL handshake
      $ curl --tlsv1.2 -s -I https://example.org | grep 'HTTP'
      HTTP/1.1 200 OK
  ```
  * [x] Do all supported symmetric ciphers use at least 256 bit keys?
  ```bash
  Test:
      $ nmap --script ssl-enum-ciphers -p 443 example.org
      PORT    STATE SERVICE
      443/tcp open  https
      | ssl-enum-ciphers:
      |   TLSv1.2:
      |     ciphers:
      |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA - strong
      |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 - strong
      |       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 - strong
      |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA - strong
      |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 - strong
      |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - strong
      |     compressors:
      |       NULL
      |_  least strength: strong
  ```
  * [x] Is the Diffie-Hellman prime at least 4096 bits?
  ```bash
  Test:
      $ openssl s_client -connect example.com:443 -cipher "EDH" |& grep "^Server Temp Key"
      Server Temp Key: DH, 4096 bits
  ```
  * [x] Have you ensured that your content cannot be embedded in a frame on another website?
  ```bash
  Test:
      $ curl -s -I https://example.org | grep '^X-Frame-Options'
      X-Frame-Options: SAMEORIGIN
      $ curl -s -I https://example_2.org | grep '^X-Frame-Options'
      X-Frame-Options: DENY # Also acceptable
  ```
  * [x] Have you ensured that the Internet Explorer content sniffer is disabled?
  ```bash
  Test:
      $ curl -s -I https://example.org | grep '^X-Content'
      X-Content-Type-Options: nosniff
  ```
  * [x] Do all assets delivered via a content delivery network include subresource integrity hashes?
  ```html
  Example:
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.2/css/bootstrap.min.css" integrity="sha384-y3tfxAZXuh4HwSYylfB+J125MxIs6mR5FOHamPBG064zB+AFeWH94NdvaCBm8qnd" crossorigin="anonymous">
  ```
  * [x] Are password entropy checks done during user sign-up, using, say [AUTH_PASSWORD_VALIDATORS](https://docs.djangoproject.com/en/1.9/topics/auth/passwords/#enabling-password-validation)?
  * [x] Are you storing only the hash of your users password, and not the cleartext password, using (say) [PBKDF](https://en.wikipedia.org/wiki/PBKDF2)?
  * [x] Are failed login attempts throttled and IP addresses banned after a number of unsuccessful attempts, using (say) [django-axes](https://pypi.python.org/pypi/django-axes)?
  * [x] Are you using [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) to throttle ssh login attempts?
  ```bash
  Test:
      $ sudo fail2ban-client status sshd
  ```
  * [x] Have you disabled password-based login over ssh, and only allowed key-based login?
  ```bash
  Test:
      $ cat /etc/ssh/sshd_config  | grep '^Password'
      PasswordAuthentication no
  ```
  * [x] Do session cookies have the 'Secure' and 'HttpOnly' flag set?
  ```bash
  Test:
      $ curl -s -I example.com/url_that_sets_cookie | grep '^Set-Cookie'
      Set-Cookie: ****;Path=/;Expires=Fri, 16-Mar-2018 19:18:51 GMT;Secure;HttpOnly;Priority=HIGH
  ```
  * [x] Do forms set a cross-site request forgery cookie?
  ```bash
  Test:
      $ curl -s -I https://example.com/url_with_form | grep '^Set-Cookie'
      Set-Cookie: csrftoken=*****************; expires=Thu, 16-Mar-2017 01:26:03 GMT;Secure;HttpOnly; Max-Age=31449600; Path=/
  ```
  * [x] Are all user uploads validated for expected content type?
  * [x] Are the permissions of all uploaded files readonly?
  * [x] Are all form fields (with the exception of password fields) validated with a restrictive regex?
  * [x] Are there unit tests (say, using [Selenium](http://www.seleniumhq.org/)) which show that one authenticated user cannot access another user's content?
  * [x] Have you made sure that database passwords, server signing keys, and hash salts are not checked into source control?
  * [x] Do you have an account recovery flow? Delete it immediately.
* [Wordpress Security Checklist](https://github.com/RafaelFunchal/wordpress-security-checklist/blob/master/items.md) - A simple checklist to improve the security of your WordPress installation.
* [NodeJS Security Checklist](https://blog.risingstack.com/node-js-security-checklist/) - A blog post about NodeJS Security by [Gergely Nemeth](https://github.com/gergelyke).
* [Ruby on Rails Security Checklist](https://blog.codeship.com/preproduction-checklist-for-a-rails-app/) - Preproduction security checklist for a rails app by [Heiko Webers](https://twitter.com/bauland42)
