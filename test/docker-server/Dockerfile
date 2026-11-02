# A throwaway Debian server for the plan 6 run: real systemd, sshd, PHP-FPM and
# nginx. Never expose it: run it with its ports bound to 127.0.0.1 only. See
# docs/superpowers/sdd/2026-10-31-michel-servers/real-run-checklist.md.
FROM debian:13

ENV DEBIAN_FRONTEND=noninteractive

# The apt lists stay in the image: Michel simulates package upgrades with apt-get -s.
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus openssh-server nginx php-fpm php-cli sudo ca-certificates

# Containers have no consoles to serve.
RUN systemctl mask getty@tty1.service console-getty.service systemd-firstboot.service

# Key sign-in only, like the servers Michel is meant for.
RUN printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/michel-test.conf \
    && useradd -m -s /bin/bash michel \
    && install -d -m 700 -o michel -g michel /home/michel/.ssh

# A finding to fix, and a canary to prove secrets are masked before storage.
RUN sed -i 's/^expose_php = .*/expose_php = On/' /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini \
    && echo 'env[DB_PASSWORD] = canari-michel-7391' >> "$(ls /etc/php/*/fpm/pool.d/www.conf)"

COPY site.conf /etc/nginx/sites-available/default
COPY index.php /var/www/html/index.php
RUN rm -f /var/www/html/index.nginx-debian.html

RUN systemctl enable ssh nginx "$(basename "$(ls /lib/systemd/system/php*-fpm.service)")"

EXPOSE 22 80
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
