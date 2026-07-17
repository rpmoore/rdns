# Resolver

* [caching](caching/) - The sharded DNS answer cache: what's stored, how it's invalidated on reload,
  and how it's sharded for concurrency.
* [rd-bit-handling](rd-bit-handling.md) - Why RD=0 gets cache-only treatment instead of full
  resolution, and where that's enforced.
* [chaos-queries](chaos-queries.md) - How rdns answers `version.bind. CH TXT`, why it's on
  by default, and where it's enforced.
* [metrics-source-ip](metrics-source-ip.md) - Which metrics carry a `source_ip` label for the
  requesting client, how it flows to Prometheus, and why some families stay unlabeled.
