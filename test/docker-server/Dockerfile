# A throwaway Debian server for the real runs of plans 6 and 7: real systemd, sshd,
# PHP-FPM, nginx and PostgreSQL, and a page that provokes errors. Never expose it:
# run it with its ports bound to 127.0.0.1 only. See
# docs/superpowers/sdd/2026-10-31-michel-servers/real-run-checklist.md and
# docs/superpowers/sdd/2026-11-02-michel-server-logs/real-run-checklist.md.
FROM debian:13

ENV DEBIAN_FRONTEND=noninteractive

# The apt lists stay in the image: Michel simulates package upgrades with apt-get -s.
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus openssh-server nginx php-fpm php-cli php-pgsql php-monolog \
    postgresql logrotate sudo ca-certificates iproute2

# Containers have no consoles to serve.
RUN systemctl mask getty@tty1.service console-getty.service systemd-firstboot.service

# Key sign-in only, like the servers Michel is meant for. The group adm is how the
# SSH user reads logs without sudo.
RUN printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/michel-test.conf \
    && useradd -m -s /bin/bash -G adm michel \
    && install -d -m 700 -o michel -g michel /home/michel/.ssh

# A finding to fix, and a canary to prove secrets are masked before storage.
RUN sed -i 's/^expose_php = .*/expose_php = On/' /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini \
    && echo 'env[DB_PASSWORD] = canari-michel-7391' >> "$(ls /etc/php/*/fpm/pool.d/www.conf)"

# The logs of plan 7. PHP-FPM writes its errors in a file of its own, as a real
# server does. The application folder holds Monolog's file.
RUN install -d -m 2750 -o www-data -g adm /var/log/php \
    && sed -i 's|^;\?error_log = php_errors.log|error_log = /var/log/php/error.log|' /etc/php/*/fpm/php.ini \
    && install -d -m 755 -o www-data -g www-data /var/www/app /var/www/app/storage /var/www/app/storage/logs

# PostgreSQL writes the error code (%e) last in the prefix, right before the severity. Its log is
# readable by adm on Debian. The site signs in as www-data, without a password.
# It listens on every address, so ss shows a database to close. Only ports 22 and 80
# leave the container, on 127.0.0.1: nothing outside can reach this database.
RUN printf "log_line_prefix = '%%m [%%p] %%q%%u@%%d %%e '\nlisten_addresses = '*'\n" > "$(ls -d /etc/postgresql/*/main)/conf.d/michel-test.conf" \
    && service postgresql start \
    && su postgres -c "psql -c 'CREATE ROLE \"www-data\" LOGIN'" \
    && service postgresql stop

COPY site.conf /etc/nginx/sites-available/default
COPY index.php errors.php /var/www/html/
RUN rm -f /var/www/html/index.nginx-debian.html

RUN systemctl enable ssh nginx postgresql "$(basename "$(ls /lib/systemd/system/php*-fpm.service)")"

EXPOSE 22 80
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
