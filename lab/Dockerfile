# php2shell lab — differential pair: PHP 8.5.11 (vulnerable) vs 8.5.12 (fixed)
# mod_php SAPI (Apache2Handler), single prefork worker for same-worker determinism.
ARG PHP_VERSION=8.5.11
FROM php:${PHP_VERSION}-apache

# One Apache child handles every request in turn — CVE-2026-109619's
# producer and consumer requests must land on the same worker.
RUN printf '<IfModule mpm_prefork_module>\n\
    ServerLimit 1\n\
    MaxRequestWorkers 1\n\
    StartServers 1\n\
    MinSpareServers 1\n\
    MaxSpareServers 1\n\
</IfModule>\n' > /etc/apache2/conf-enabled/00-single-worker.conf \
# Per-directory php_value/.htaccess must apply early (INI-diagnostic consumer
# path of CVE-2026-109619); the stock image ships AllowOverride None.
 && printf '<Directory /var/www/html>\n\
    AllowOverride All\n\
</Directory>\n' > /etc/apache2/conf-enabled/00-allow-override.conf

COPY php-override.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY html/ /var/www/html/
