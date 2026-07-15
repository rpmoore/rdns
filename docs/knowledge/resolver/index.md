# Resolver

* [caching](caching/) - The sharded DNS answer cache: what's stored, how it's invalidated on reload,
  and how it's sharded for concurrency.
* [rd-bit-handling](rd-bit-handling.md) - Why RD=0 gets cache-only treatment instead of full
  resolution, and where that's enforced.
* [chaos-queries](chaos-queries.md) - How rdns answers `version.bind. CH TXT`, why it's on
  by default, and where it's enforced.
