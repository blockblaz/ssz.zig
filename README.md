[![Lint and test](https://github.com/gballet/ssz.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/gballet/ssz.zig/actions/workflows/ci.yml)

# ssz.zig
A [Zig](https://ziglang.org) implementation of the [SSZ serialization protocol](https://github.com/ethereum/eth2.0-specs/blob/dev/ssz/simple-serialize.md).

This is meant to work with zig version 0.17.0.

## Serialization

Use `serialize` to write a serialized object to a byte buffer.

Currently supported types:

 * `BitVector[N]`
 * `uintN`
 * `boolean`
 * structures
 * optionals
 * `null`
 * `Vector[N]`
 * **tagged** unions
 * `List[N]`
 * `Bitlist[N]`
 * `ProgressiveList[T]`
 * `ProgressiveBitlist`

Ziglang has the limitation that it's not possible to determine which union field is active without tags.

## Deserialization

Use `deserialize` to turn a byte array containing a serialized payload, into an object.

`deserialize` does not allocate any new memory. Scalar values will be copied, and vector values use references to the serialized data. Make a copy of the data if you need to free the serialized payload. Future versions will include a version of `deserialize` that expects an allocator.

Supported types:

 * `uintN`
 * `boolean`
 * structures
 * strings
 * `BitVector[N]`
 * `Vector[N]`
 * unions
 * optionals
 * `List[N]`
 * `Bitlist[N]`
 * `ProgressiveList[T]`
 * `ProgressiveBitlist`

## Merkelization (experimental)

Use `tree_root_hash` to calculate the root hash of an object.

Supported types:

 * `Bitvector[N]`
 * `boolean`
 * `uintN`
 * `Vector[N]`
 * structures
 * strings
 * optionals
 * unions
 * `List[N]`
 * `Bitlist[N]`
 * `ProgressiveList[T]`
 * `ProgressiveBitlist`

## Progressive types (EIP-7916)

`ProgressiveList(T)` and `ProgressiveBitlist` implement
[EIP-7916](https://eips.ethereum.org/EIPS/eip-7916). They serialize exactly like
`List(T, N)` and `Bitlist(N)`, but carry no capacity limit and merkleize with
`merkleizeProgressive`: a 0-terminated sequence of binary subtrees whose leaf
counts grow 1, 4, 16, 64, ... This costs fewer hashes for short lists and keeps
generalized indices stable as the list grows.

```zig
const Transactions = ssz.utils.ProgressiveList(u64);
var txs = try Transactions.init(allocator);
defer txs.deinit();
try txs.append(42);
try ssz.hashTreeRoot(Sha256, Transactions, txs, &root, allocator);
```

`ProgressiveByteList` is an alias for `ProgressiveList(u8)`.

A struct opts in to EIP-7495 / EIP-7688 `ProgressiveContainer(active_fields=[1] * N)`
merkleization by declaring a marker. Serialization is unchanged; only the root
differs, becoming `hash(merkleize_progressive(field_roots), pack_bits(active_fields))`.

```zig
pub const ExecutionPayload = struct {
    pub const ssz_progressive_container = true;
    parent_hash: [32]u8,
    // ...
};
```

Only the all-active form EIP-7688 mandates is supported; `active_fields` is
derived from the field count, so there is no way to mark a field inactive.

Two consequences of having no `N`:

 * `maxInLength` returns `error.NoMaxInLengthAvailable`, so `deserialize` cannot
   reject an oversized payload up front. Decoding still allocates only in
   proportion to the input, but callers that relied on `N` as a cheap sanity
   bound should enforce their own context-specific limit, as the EIP recommends.
 * `TreeHasher` cannot wrap a progressive type: a progressive tree has no fixed
   depth, so the power-of-two Merkle cache does not apply. Using it is a compile
   error.

## Using Custom Hash Functions

ssz.zig is hash-function agnostic. Pass your hasher as a type parameter:

```zig
const std = @import("std");
const ssz = @import("ssz.zig");

// Using SHA256 (from stdlib)
const Sha256 = std.crypto.hash.sha2.Sha256;
try ssz.hashTreeRoot(Sha256, MyType, value, &root, allocator);

// Using a custom hasher (must implement init/update/final API)
const MyHasher = ...; // Your hasher type
try ssz.hashTreeRoot(MyHasher, MyType, value, &root, allocator);
```

**Required Hasher API:**
```zig
pub const Options = struct {};
pub fn init(_: Options) Self;
pub fn update(self: *Self, data: []const u8) void;
pub fn final(self: *Self, out: *[Self.digest_length]u8) void; // out size matches 32 bytes for SSZ
```

## Contributing

Simply create an issue or a PR.
