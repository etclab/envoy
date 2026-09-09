# RBE cert validator — proposed changes

Implementation spec for reworking the RBE TLS certificate validator so it stops
costing ~1 ms of CPU per handshake. Written to be self-contained: every API
name, file path and line number below was checked against this tree, and every
performance claim comes from a measured run named in
[Evidence](#evidence-where-the-cost-actually-is).

Files in scope:

| Path | Role |
| --- | --- |
| `rbe_validator.cc` / `.h` | the validator being changed |
| `BUILD` | deps to add and remove |
| `api/envoy/extensions/transport_sockets/tls/v3/tls_rbe_validator_config.proto` | gains a `GrpcService` field |
| `source/common/tls/ssl_socket.cc` | `resumeHandshake()` — do not regress, see [Pitfalls](#pitfalls) |

Reference implementation to copy from — it calls the *same* gRPC service
(`envoy.service.auth.v3.Authorization/Check`) asynchronously and correctly:
`source/extensions/filters/common/ext_authz/ext_authz_grpc_impl.{h,cc}`.

---

## The problem in one paragraph

`doVerifyCertChain()` spawns **one OS thread per TLS handshake**
(`rbe_validator.cc:164`), each of which makes a **blocking** gRPC call over a
UDS with a 5 s deadline (`rbe_validator.cc:207`), posts its result back to the
worker's dispatcher, and is then **`join()`ed from inside the dispatcher
callback** (`rbe_validator.cc:254`). At benchmark load this is ~100–250 thread
create/destroy cycles per second per sidecar, each with a default 8 MB stack.
The pattern came from Envoy Mobile's platform-bridge validator, which spawns a
thread because it must call a synchronous Android/iOS trust-store API and does
a handful of handshakes per session. A server-side sidecar at 1,000+
handshakes/s has neither the constraint nor the budget.

Envoy's cert-validator API is already async: returning
`ValidationResults::ValidationStatus::Pending` and completing later through the
`Ssl::ValidateResultCallbackPtr` is what makes it asynchronous. **The thread
contributes nothing to the asynchrony — it is pure overhead.**

---

## Evidence: where the cost actually is

From `DeathStarBench/socialNetwork/results/envoy-diag-09-07-26_114514`
(2x replicas, `CONN_REUSE=0`, `proxyCPULimit=1` so `concurrency=1`), Mazu arm
vs an Istio control arm on the same fleet at the same handshake rate.

productpage sidecar, the fan-out node:

| arm | rps target | achieved | proxy threads | cores | throttled | `upstream_cx_connect_ms` p50 | p90 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| istio | 100 | 95.4 | 10 → 10 | 0.45 | 0% | 6.0 ms | **8.0 ms** |
| istio | 400 | 359.3 | 10 → 10 | 0.93 | 2% | 19.9 ms | 42.3 ms |
| mazu | 100 | 95.3 | 33 → **98** | 0.52 | 7% | 78.2 ms | **546 ms** |
| mazu | 400 | **232.6** | 28 → **98** | 0.86 | **34%** | 78.3 ms | 529 ms |

CPU accounting at the ceiling (blended over inbound+outbound handshakes; the
*delta* and the system-time fraction are the robust parts):

| arm | user | sys | sys % | CPU/handshake | sys/handshake |
| --- | --- | --- | --- | --- | --- |
| istio @400 | 0.75 | 0.18 | 19% | 2,458 µs | 476 µs |
| mazu @400 | 0.63 | 0.23 | **27%** | **3,504 µs** | **936 µs** |

RBE validation adds **~1 ms CPU per handshake**, and **system time per
handshake roughly doubles**. Kernel time doubling while user time rises only
modestly is the signature of thread create/destroy — 8 MB stack
`mmap`/`munmap`, page-table teardown with TLB shootdown across a 32-core node,
`mmap_lock` taken in write mode (which also stalls page faults on the Envoy
worker), futex and join. At ~250 handshakes/s that is **~0.25 cores of pure
overhead** on a 1-core budget where the Istio control already needs 0.94 cores
to reach its own ceiling. That is the measured 1.6× throughput gap.

The 34% throttling is a *consequence*, not the cause: Mazu averages **less**
CPU than Istio (0.85 vs 0.94 cores) while being frozen a third of the time,
because ~70 threads block on gRPC and their replies wake them together, so
demand bursts past the quota in 100 ms chunks. The 500–600 ms `connect_ms`
plateau is that quota queueing — flat across an 8× range of offered load.

### Ruled out by measurement — do not spend time here

- **kube-apiserver / TokenReview.** TokenReviews were flat at ~34/s while
  handshakes tripled to 1,272/s; p99 4.95 ms; APF in-queue **0**; inflight
  max 13. The agent's cache is hitting ~97%.
- **The agent's verification work.** In `istio.git`, `checkWithToken()`'s
  normal path (`security/pkg/nodeagent/extauthz/server.go:216-266`) is an md5
  of the token, a `regStore` map lookup, a *precomputed* `reg.PodValid` bool,
  and a TokenReview cached 2 s with singleflight coalescing. No pairing crypto.
  The five-operation path with crypto only runs under
  `MAZU_BENCHMARK_INLINE_ENABLED`, which defaults to false.
- **Envoy event-loop stalls.** `server.worker_0.watchdog_miss` was exactly 0 in
  both arms at every load — no 200 ms+ single-callback blocks. (Weak
  instrument for whole-container freezes, since the guarddog is frozen too, but
  it does rule out a long block inside one callback.)
- **Envoy pool queueing.** `downstream_pre_cx_active` peaked at 29 for Mazu vs
  **34 for Istio**; `upstream_cx_connect_fail`, `upstream_cx_connect_timeout`
  and `upstream_rq_pending_overflow` all 0.
- **Envoy-side logging.** All six `ENVOY_LOG_MISC(info, ...)` calls in
  `rbe_validator.cc` are suppressed: the run had `log_level: warning` and
  `component_log_level: misc:error`.

---

## Change 1 — cache and coalesce in the validator (done)

Implemented on the existing thread-based transport, as described below. See
[What Change 1 actually landed](#what-change-1-actually-landed) for the shape of
the code and the two things that turned out differently from this plan.

Highest ratio of win to risk, and independent of the threading model.

At 2x replicas the proxy makes ~1,272 RPCs/s to answer ~**24** distinct
questions: there are only ~24 peer pods, and the agent already caches each
answer for 2 s. The same work is being done twice — cached in the agent,
uncached in Envoy. A validator-side cache takes Envoy's RPC rate from
`O(handshakes)` to `O(peers / TTL)`, roughly a 50× reduction in the traffic
that generates the CPU bursts.

- Key on the **admin token**, hashed. `5b7960837e` ("update envoy to use hashed
  token as key") already had this; `5e35305ded` removed the map without putting
  a cache back. Do not key on the peer IP alone — IPs are reused across pods.
- TTL must be **≤ the agent's `tokenCacheTTL`** (currently **1 s**,
  `security/pkg/nodeagent/extauthz/server.go:48`), so Envoy never widens the
  revocation window by more than one agent TTL. Make it configurable in
  `RBECertValidatorConfig` with a default of 1 s, and state the revocation
  bound in the proto comment. Note the bound is **additive**: with both TTLs at
  1 s a revoked peer can be admitted for up to ~2 s after revocation, because
  Envoy may cache an answer the agent had already been holding for a second.
- Cache **both** verdicts. A cached deny is what stops a rejected peer from
  re-driving the full path on every reconnect.
- **Single-flight**: today N concurrent handshakes from the same peer produce N
  threads and N independent RPCs. Attach later waiters to the in-flight
  request and complete them all from the one response.
- Put the cache in **thread-local storage**, not behind a shared mutex. Each
  worker gets its own; entries are cheap and a shared lock on the handshake
  path is exactly the kind of contention being removed. `ThreadLocal::TypedSlot`
  (`envoy/thread_local/thread_local.h:111`) is the mechanism, reachable via
  `CommonFactoryContext::threadLocal()` (`envoy/server/factory_context.h:117`).

Add counters — `rbe.cache_hit`, `rbe.cache_miss`, `rbe.coalesced`,
`rbe.check_failure` — so the hit rate is measurable rather than assumed. Note
that Istio's `statsInclusionPrefixes` annotation is an Envoy `stats_matcher`
**inclusion_list**: stats outside it are never instantiated, so a new `rbe.*`
scope will be invisible unless the prefix list is widened. See
[Verification](#verification).

### What Change 1 actually landed

| Piece | Where |
| --- | --- |
| `cache_ttl` config field, default 1 s | `tls_rbe_validator_config.proto` |
| per-worker cache + single-flight table | `RBEValidator::ThreadLocalCache` |
| cache lookup / coalesce / issue | `doVerifyCertChain()` steps 3–6 |
| verdict store + fan-out to waiters | `onVerificationComplete()` |
| `rbe.cache_hit` / `cache_miss` / `coalesced` / `check_failure` | `RBEValidator::RBEStats` |

Two things differ from the plan above:

- **A cache hit is answered synchronously**, not through the callback. It
  returns `ValidationStatus::Successful`/`Failed`, and
  `ContextImpl::customVerifyCertChain` (`context_impl.cc:533`) completes the
  handshake in place — no `Pending`, no dispatcher round trip, no
  `resumeHandshake()`. The unused `ValidateResultCallbackPtr` is simply dropped;
  `onCertificateValidationCompleted(..., /*async=*/false)` clears the latch that
  `createValidateResultCallback()` set.
- **The thread handles still need a shared, mutex-guarded map** for the
  destructor to join them — `~PosixThread` asserts the thread was joined
  (`thread_impl.cc:122`) and there is no detach. It is keyed on a `uint64_t`
  request id rather than `pthread_t`, which retires the recycled-identifier
  hazard from [Change 3](#change-3--smaller-fixes-valid-regardless-of-the-above)
  early. That map is touched once per **cache miss**, not once per handshake, so
  it is off the hot path, and Change 2 deletes it outright.

Transport-level failures (gRPC error, deadline) are delivered to the waiters but
**not** cached, and bump `rbe.check_failure`; only real allow/deny verdicts are
stored. The verdict map is bounded at 1,024 entries per worker — the steady
state is the peer-pod count, the bound only exists so identity churn cannot grow
it without limit.

## Change 2 — replace thread-per-handshake with `Grpc::AsyncClient`

`RBEValidator`'s constructor already receives
`Server::Configuration::CommonFactoryContext&`, which exposes everything needed:

```
envoy/server/factory_context.h:122   virtual Upstream::ClusterManager& clusterManager() PURE;
envoy/upstream/cluster_manager.h:408   virtual Grpc::AsyncClientManager& grpcAsyncClientManager() PURE;
envoy/server/factory_context.h:117   virtual ThreadLocal::SlotAllocator& threadLocal() PURE;
```

### Shape

Make `RBEValidator` derive from
`Grpc::AsyncRequestCallbacks<envoy::service::auth::v3::CheckResponse>`
(`source/common/grpc/typed_async_client.h:72`), which requires:

```cpp
void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
void onSuccess(std::unique_ptr<CheckResponse>&& response, Tracing::Span&) override;
void onFailure(Grpc::Status::GrpcStatus status, const std::string& message,
               Tracing::Span&) override;
```

Resolve the method descriptor once, exactly as ext_authz does
(`ext_authz_grpc_impl.cc:82`):

```cpp
service_method_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
    "envoy.service.auth.v3.Authorization.Check"))
```

In `doVerifyCertChain()`, after the cache misses:

```cpp
Http::AsyncClient::RequestOptions options;
options.setTimeout(timeout_);                       // see Change 3 on the value
auto* request = client->send(service_method_, check_req, *this, span, options);
```

`send()` is declared at `source/common/grpc/typed_async_client.h:118`. Stash
the `Ssl::ValidateResultCallbackPtr` keyed by the returned
`Grpc::AsyncRequest*`, return `Pending`, and in `onSuccess`/`onFailure` look it
up and call `onCertValidationResult(...)` directly — **you are already on the
correct worker thread**, so there is no `post`, no `join`, and no
`alive_indicator_` dance.

### Obtaining the client

The validator object is shared across workers, so the client cannot be. Two
options, both fine:

1. **Simplest** — call
   `grpcAsyncClientManager().getOrCreateRawAsyncClient(grpc_service, scope, /*skip_cluster_check=*/true)`
   from `doVerifyCertChain()` (i.e. on the worker). It is documented as
   "cached thread locally and shared across different filter instances"
   (`envoy/grpc/async_client_manager.h`), so this returns the calling worker's
   client. Returns `absl::StatusOr` — handle the error rather than dereferencing.
2. **Explicit** — store an `AsyncClientFactoryPtr` from
   `factoryForGrpcService(...)` in the constructor and a
   `ThreadLocal::TypedSlot` holding one client per worker.

Prefer (1) unless profiling shows the per-call lookup matters; it is less code
and less lifetime to reason about.

### What this deletes

`thread_factory_`, the `ValidationJob` struct, `validation_thread_`,
`validation_jobs_` and `validation_jobs_mu_`, `alive_indicator_`,
`performExtAuthzCheck()`, `onVerificationComplete()`, the destructor's join
loop (`rbe_validator.cc:55-70`), and the `grpc::CreateChannel` /
`ext_authz_stub_` members (`rbe_validator.cc:47-50`).

It also removes the **18 threads the proxy carries at idle** — measured 28 for
Mazu against 10 for the Istio control, before any load. Those are grpc++'s own
polling, timer and executor threads for the sync channel, and they go away with
the grpc++ dependency.

### Config prerequisite (this is the part that needs work outside Envoy)

`envoy_grpc` routes through a named Envoy **cluster**
(`api/envoy/config/core/v3/grpc_service.proto:33`, `cluster_name`), so the UDS
endpoint has to exist as one. `envoy.config.core.v3.Address` supports a `pipe`
address (`api/envoy/config/core/v3/address.proto:183`), so a static cluster
pointing at `./etc/istio/proxy/ext-authz.sock` is what is needed. In an Istio
sidecar that means adding it via `EnvoyFilter` (`ADD` on `CLUSTER`) or a
bootstrap override — **verify which of these the deployment actually uses
before writing code against it.**

Add a `envoy.config.core.v3.GrpcService grpc_service` field to
`RBECertValidatorConfig` (currently an empty message) rather than hardcoding
the socket path, so the cluster name is configuration.

`google_grpc` would accept `unix:./etc/istio/proxy/ext-authz.sock` directly
with no cluster and no `EnvoyFilter` — but it is grpc++ underneath and brings
its own thread pool back, which is the thing being removed. Use it only as a
temporary bring-up shortcut, never as the endpoint of this work.

## Change 3 — smaller fixes, valid regardless of the above

- **Never `join()` from the dispatcher** (`rbe_validator.cc:254`). It is an
  unbounded block on the event loop. `watchdog_miss` was 0 so it is not costing
  200 ms today, but if any thread survives this rework, detach and self-reap
  instead.
- **The 5 s deadline** (`rbe_validator.cc:207`) is why the 2x/100rps p99 was
  5.95 s — a validation that times out fails the handshake, the peer reconnects,
  and the work is re-done. Against a service that answers in ~5 ms, 5 s is a
  queue, not a timeout. With a cache and an async client, set it in the tens of
  milliseconds and make it configurable.
- **Drop the `pthread_t`-keyed map.** `PosixThread::pthreadId()` returns the
  glibc thread-descriptor address (`source/common/common/posix/thread_impl.cc`,
  `ThreadId(static_cast<int64_t>(thread_handle_->handle()))`), which glibc
  recycles from its stack cache. Keying shared state on a recycled identifier
  is a hazard even where the current join-before-reuse ordering makes it safe
  today. Change 2 replaces the key with the `AsyncRequest*` anyway.
- **Cancel in flight on connection teardown.** If a connection dies while a
  validation is outstanding, the request must be cancelled
  (`Grpc::AsyncRequest::cancel()`, cf. `GrpcClientImpl::cancel()`) and the
  stashed callback dropped without invoking it. Check what the current code
  does here — it holds the callback in a map and may invoke it against a
  destroyed socket.

---

## Pitfalls

- **Do not regress `resumeHandshake()`.** Commit `a3a3f97711` added a
  `callbacks_->setTransportSocketIsReadable()` call in
  `source/common/tls/ssl_socket.cc` for the case where BoringSSL has already
  drained application data into its internal buffer during async validation, so
  no further read event fires and the connection stalls. That fix is still
  needed with an async client — the async-completion path is unchanged, only the
  transport under it. Its guard is `info_->state() == HandshakeComplete`; if a
  connection can resume while still `HandshakeInProgress`, that case is
  currently unhandled and worth a test.
- **`onSuccess` runs on the worker thread that issued `send()`.** That is the
  point. Do not add any cross-thread posting back.
- **`getOrCreateRawAsyncClient` returns `absl::StatusOr`.** A failure here is a
  config error, not a validation failure — fail the handshake with a distinct
  error string and bump a distinct counter so the two are not conflated.
- **Both peers validate each other.** Every connection drives two validations,
  one per side, so per-request cost is `2 × handshakes`. Measured: productpage
  does 5,737 handshakes to details and 5,737 to reviews per 120 s step.
- **`concurrency` follows the sidecar CPU limit.** The measured runs had
  `proxyCPULimit: "1"` → `concurrency: 1`, i.e. a single worker. Confirm from
  `/server_info` → `command_line_options.concurrency` before interpreting any
  result; the 09-05 runs had 2.

## Verification

The harness already exists in `DeathStarBench/socialNetwork`:

```
collect_envoy_stats.sh          snapshot | sample | apiserver
run-2x-envoy-diag.sh            2x, both arms, ENVOY_DIAG=1, widened stats
parse_envoy_diag.py             one table + a verdict per hypothesis
```

`./run-2x-envoy-diag.sh` then `python3 parse_envoy_diag.py results/envoy-diag-<date>`.

Success looks like, on the productpage sidecar:

| metric | before | target |
| --- | --- | --- |
| proxy threads under load | 28 → 98 | flat, ~10 |
| `upstream_cx_connect_ms` p90 | 546 ms | within ~2× of the Istio arm (8–42 ms) |
| throttled share of wall clock | 34% | single digits |
| sys CPU per handshake | 936 µs | approaching the Istio arm's 476 µs |
| achieved rps at 400 target | 232.6 | approaching the Istio arm's 359 |
| ext_authz RPCs/s | ~1,272 | `O(peers / TTL)`, tens |

Three collection traps, all hit during the 09-07 run and all fixed in those
scripts — re-read them before trusting any new numbers:

1. `sidecar.istio.io/statsInclusionPrefixes` is an Envoy `stats_matcher`
   inclusion_list. Excluded stats are **never instantiated**, so `server.*` and
   `ssl.*` did not exist in the proxies at all. `run-2x-envoy-diag.sh` widens it
   through `STATS_PREFIXES`; a new `rbe.*` scope must be added to that list.
2. Watchdog counters are scoped **per thread** —
   `server.worker_0.watchdog_miss`, not `server.watchdog_miss`. Querying the
   latter matches nothing, which reads as "zero, ruled out".
3. `/stats?usedonly` omits never-incremented counters, making "zero" and
   "does not exist" indistinguishable. Use plain `/stats`.

## BUILD changes

Add — each of these was checked to exist in this tree, and the first five are
exactly what `source/extensions/filters/common/ext_authz/BUILD` uses for the
same job:

```
"//envoy/grpc:async_client_interface",
"//envoy/grpc:async_client_manager_interface",
"//envoy/upstream:cluster_manager_interface",
"//source/common/grpc:async_client_lib",
"//source/common/grpc:typed_async_client_lib",
"//envoy/thread_local:thread_local_interface",       # only if using TypedSlot
"@envoy_api//envoy/config/core/v3:pkg_cc_proto",     # for the GrpcService config field
```

Remove once the threads are gone:

```
"@com_github_grpc_grpc//:grpc++",
"//source/common/common:thread_impl_lib_posix",
"//envoy/thread:thread_interface",
"@envoy_api//envoy/service/auth/v3:pkg_cc_grpc",   # keep pkg_cc_proto for the messages
```

Note the `pkg_cc_grpc` → `pkg_cc_proto` swap: the async client needs the
`CheckRequest`/`CheckResponse` **messages** but not the generated gRPC stubs,
because it dispatches by method descriptor rather than through a stub. Dropping
`grpc++` is what removes the 18 idle threads, so confirm it is genuinely gone
from the link — a leftover transitive dep will keep them, and the thread count
at idle (`/proc/<envoy>/status`) is the cheapest way to check.

## Suggested order

1. ~~Change 1 (cache + single-flight) on the existing thread-based transport.~~
   **Done.** Re-run the harness — RPC rate should fall ~50× and throttling
   should drop sharply. Not yet measured; `rbe.*` must be added to
   `STATS_PREFIXES` first or the new counters will not exist. This is a real win
   on its own and de-risks the rest.
2. Change 2 (async client), behind the new `grpc_service` config field so both
   transports can coexist during bring-up.
3. Change 3 cleanups, and delete the thread machinery once (2) is proven.

## Out of scope / open

- **The 4x–16x regime is unexplained.** In
  `results/benchmark1.5b-replica-scale-09-05-26_121802`, sidecars sat at
  **0.05–0.2 cores** with a 2-core limit — far deeper idle than the 0.85 cores
  measured at 2x, so this mechanism probably does not explain it. Needs the
  same instrumentation at 4x before anyone theorises.
- **Agent-side latency was never measured directly.**
  `extAuthzLog.Infof("[dev] checkWithToken: total duration=%v", ...)` fires on
  every Check at default info level in the istio-proxy container log. Capturing
  it during a Mazu run would conclusively separate agent time from Envoy time.
  It was not captured because the sweep only dumps sidecar logs for pods that
  restarted.
- **Benchmark comparability.** `MAZU_BENCHMARK_INLINE_ENABLED`
  (`dev/deploy-mazu-configmap.sh`, default false) switches the agent to a
  five-operation path including pairing crypto; `a6d8553354` cut
  challenge-response there from ~170 ms to ~53 ms. Runs with it on and off are
  different cost regimes and must not be compared.
- **Connection reuse.** The measured runs used `CONN_REUSE=0`
  (`maxRequestsPerConnection=1`), so every request paid fresh handshakes. That
  is the worst case for this code path and the right setting for testing it,
  but it is not the steady state of a normally-pooled mesh. Report both.
