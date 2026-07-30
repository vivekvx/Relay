id: why-postgres-ratelimit
shareable: true
shareable_with: vivek
tags: ratelimit,postgres,architecture

We chose a Postgres-backed counter for rate limiting instead of Redis.
At our current scale (dozens of senders, not millions), pulling in
Redis just to count requests per hour would add a second stateful
service to operate, back up, and reason about during an incident, for
a problem a single indexed table already solves. rate_limit_events logs
one row per request; a query over a trailing one-hour window gives us
the exact same sliding-window behavior Redis's INCR+EXPIRE pattern
gives, without a new dependency. If we ever need sub-millisecond checks
at very high volume, Redis is the obvious next step — but that's not
the problem we have today, and CLAUDE.md is explicit that this is a
locked decision, not a placeholder waiting to be swapped out.
