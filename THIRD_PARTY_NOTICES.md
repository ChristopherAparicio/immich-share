# Third-party software and licence boundaries

The MIT licence in this repository applies only to the original
`immich-share` orchestration, controller, configuration templates and
documentation, except where a file says otherwise. It does not relicense any
third-party project or derivative work.

## Immich Public Proxy

The public gallery application is the separately maintained
[`ChristopherAparicio/immich-public-proxy`](https://github.com/ChristopherAparicio/immich-public-proxy)
fork. It preserves the upstream history and is licensed under AGPL-3.0-only.
Deployments consume its immutable GHCR image; the corresponding source, full
AGPL licence and fork notices are published in that repository and linked from
every interactive page served by the application.

Historical `immich-share` commits before the external-fork migration included
an IPP build wrapper and source-level patch material under `vps/`. Those files
were derived from Immich Public Proxy and must be treated as AGPL-3.0-only,
irrespective of the top-level MIT licence present in those commits. They are no
longer part of the current tree.

## Other components

Immich, Caddy, the Caddy rate-limit module, nginx, WireGuard and the container
base images remain subject to their respective upstream licences. This
repository configures or references them; it does not relicense them.
