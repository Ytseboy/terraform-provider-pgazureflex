FROM postgres:16-alpine

RUN apk add --no-cache gcc musl-dev

COPY test/docker/pgaadauth_mock.c /tmp/pgaadauth_mock.c
RUN gcc -fPIC -shared -I"$(pg_config --includedir-server)" \
    /tmp/pgaadauth_mock.c -o "$(pg_config --pkglibdir)/pgaadauth_mock.so" \
    && rm -f /tmp/pgaadauth_mock.c

COPY test/azure_flex_sim.sql /docker-entrypoint-initdb.d/01-azure-flex-sim.sql
