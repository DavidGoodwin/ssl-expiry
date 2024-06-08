# What ?

Crude took to check remote ssl certificates (mostly warns when they expire soon)


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

If you need to check a different underlying address (e.g. cloudflare is proxying/hiding the actual server, and you need to check the origin server has a valid certificate) then try : 


e.g. connect to the server with IP 1.2.3.4 and look for an ssl certificate for the virtual host 'myserver.com' and check it's valid.

```
myserver.com#1.2.3.4
```



e.g. connect to this SMTP server (port 25) on IP 4.5.6.7 looking for the certificate mail.example.com ...

```
mail.example.com:25#4.5.6.7
```
