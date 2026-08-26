# IPP 3.2.1, pinned by digest. npm/corepack are required only during the build.
# upstream; the production application starts directly with `node dist/index.js`.
FROM alangrainger/immich-public-proxy@sha256:7ca34cc3efa618a11674db00e1d943e4611cb2e14d1f6d73343757db700a6e3c

USER root
RUN apk upgrade --no-cache
COPY patch-ipp-download-limit.mjs /tmp/patch-ipp-download-limit.mjs
RUN node /tmp/patch-ipp-download-limit.mjs \
 && rm /tmp/patch-ipp-download-limit.mjs \
 && node --check /app/dist/stream/download.js \
 && node --check /app/dist/view/gallery.js
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/bin/corepack
USER node
