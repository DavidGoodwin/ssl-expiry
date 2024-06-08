# What ?

Crude took to check remote ssl certificates.

![PHP Composer](https://github.com/DavidGoodwin/ssl-expiry/workflows/PHP%20Composer/badge.svg)

# Installation

Run via cron (php check.php). If it outputs anything, you probably need to do something.

Requires '''openssl''' and PHP (PHP, because I'm too lazy to do it all in bash)

# Configuration 
Add hosts to 'hosts.conf' one per line.

By default, it assumes you wish to check port 443 (https). If you want to check a different port then do host:port (e.g. mail.mydomain.com:25)

e.g.

```
myserver.com
mail.example.com:25
```

If you need to check a different underlying address (e.g. cloudflare is proxying/hiding the actual server, and you need to check the server has a valid certificate) then try : 


e.g.

```
myserver.com#1.2.3.4
mail.example.com:25#4.5.6.7
```
