# Invariant Status Message Format

An invariant status message (as accepted by the dashboard app and posted by the geth client)
communicates the status of a single entity being monitored. We will call this entity (liquidity pool,
token, etc.) a _monitor target_. Each monitor target should have a unique ID: for an on-chain monitor
target this will likely be the address of the entity; e.g. the token address.

The status message is a plain JSON object. It **must** include the ID of the monitor target, however the
field of the object used to store this ID is unspecified, provided it does not collide with any of the fields
specified below; `"id"` is sensible choice.

In addition to the monitor target's id, the status message must also include the following fields

1. `invariantStatus`, which must be a `string` that is either:
    * `error` indicating the invariant checking process failed
    * `success` indicating that all invariants hold for the monitor target, or
    * `failure` indicating that at least one invariant for a monitor target does not hold
2. `blockNumber`: a JSON number which holds the blocknumber on which this invariant was checked
3. `calculationTimestamp`: a JSON number holding the UNIX timestamp at which at which the invariant check was performed. It it not specified whether this the time before, after, or during the invariant check, although immediately after is a reasonable choice.

Depending on the value of `invariantStatus`, the following fields may also appear.

If the `invariantStatus` was `error`, then there **must** be a field with the key `error` containing a JSON string describing the
error. NB it is not currently possible to report partial error results.

If `invariantStatus` was `success` or `failure`, then there must be a `conditionsChecked` field which holds a non-empty array
of condition objects.

## Condition Object Specification

Each condition object describes the individual condition (or invariant) checked for the monitor target. Each condition object
must have the following fields:
1. `condition`: a JSON string, holding a name of the condition that was checked. **Should** be unique within the list of `conditionsChecked` for a monitor target
2. `status`: a JSON boolean, indicating if the condition was true (that is, the invariant held).
3. `values`: A JSON dictionary holding arbitrary key-values that can communicate descriptive information about the condition checked. For example, if the condition involves solvency of a lending protocol, this dictionary can contain information about the total debt of the protocol.
