const std = @import("std");
const lib = @import("./lib.zig");
const zeros = @import("./zeros.zig");

const BYTES_PER_CHUNK = lib.BYTES_PER_CHUNK;
const chunk = lib.chunk;
const zero_chunk = lib.zero_chunk;

/// Depth at which a List/Bitlist of `chunk_limit` chunks must be merkleized,
pub fn targetDepth(comptime chunk_limit: usize) usize {
    if (chunk_limit <= 1) return 0;
    return @bitSizeOf(usize) - @clz(chunk_limit - 1);
}

/// A grow-on-demand cached Merkle tree, generic over the hash function.
///
/// Flat 0-indexed binary tree: root at nodes[0], children of i at 2i+1/2i+2,
/// leaves at nodes[capacity-1 .. 2*capacity-1].
pub fn MerkleCache(comptime Hasher: type) type {
    comptime std.debug.assert(Hasher.digest_length == BYTES_PER_CHUNK);
    return struct {
        const Self = @This();
        /// Zero-subtree roots for this hasher. Index i is the root of an
        /// all-zero subtree with 2^i leaves. Depth 64 covers any usize limit.
        const hashes_of_zero = zeros.buildHashesOfZero(Hasher, BYTES_PER_CHUNK, 64);

        nodes: []chunk,
        capacity: usize,
        dirty_low: ?usize,
        dirty_high: ?usize,
        cached_length: usize,
        cached_root: chunk,
        root_valid: bool,

        pub fn init() Self {
            return .{
                .nodes = &.{},
                .capacity = 0,
                .dirty_low = null,
                .dirty_high = null,
                .cached_length = 0,
                .cached_root = zero_chunk,
                .root_valid = false,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.capacity > 0) allocator.free(self.nodes);
            self.* = init();
        }

        /// Ensure the tree can hold `required_chunks` leaves. Growing reallocates
        /// the node array, but the existing tree is exactly the leftmost subtree
        /// of the larger one, so we transplant its already-computed nodes into
        /// their shifted positions instead of rehashing them.
        ///
        /// Old level `d` (indices [2^d-1, 2^d-1+2^d)) maps to new level `d+k`
        /// where `k = new_depth - old_depth`. Only the newly exposed leaf slots
        /// [old_cap, new_cap) are marked dirty; the transplanted subtree is
        /// reused, and the content-addressed refresh dirties any old leaf that
        /// actually changed.
        pub fn ensureCapacity(self: *Self, allocator: std.mem.Allocator, required_chunks: usize) !void {
            if (required_chunks <= self.capacity) return;
            const new_cap = try std.math.ceilPowerOfTwo(usize, required_chunks);
            if (new_cap == self.capacity) return;
            const new_nodes = try allocator.alloc(chunk, 2 * new_cap - 1);
            @memset(new_nodes, zero_chunk);

            const old_cap = self.capacity;
            if (old_cap > 0) {
                const old_depth = std.math.log2_int(usize, old_cap);
                const new_depth = std.math.log2_int(usize, new_cap);
                const k = new_depth - old_depth;
                // Transplant the old tree level by level into the leftmost
                // subtree of the new tree (no rehashing).
                var d: usize = 0;
                while (d <= old_depth) : (d += 1) {
                    const count = @as(usize, 1) << @intCast(d);
                    const old_start = count - 1; // 2^d - 1
                    const new_start = (@as(usize, 1) << @intCast(d + k)) - 1; // 2^(d+k) - 1
                    // The old tree is the leftmost subtree of the new one, so the
                    // old leaves land at new indices [new_cap-1, new_cap-1+old_cap)
                    // and every transplanted block stays within the new buffer.
                    std.debug.assert(new_start + count <= new_nodes.len);
                    @memcpy(new_nodes[new_start .. new_start + count], self.nodes[old_start .. old_start + count]);
                }
                allocator.free(self.nodes);
            }

            self.nodes = new_nodes;
            self.capacity = new_cap;
            // Reuse the transplanted left subtree; only the newly exposed leaf
            // slots need recomputing (plus any old leaf the refresh re-dirties).
            self.dirty_low = if (old_cap > 0) old_cap else 0;
            self.dirty_high = new_cap - 1;
            self.root_valid = false;
        }

        pub fn leafPtr(self: *Self, index: usize) *chunk {
            std.debug.assert(index < self.capacity);
            return &self.nodes[self.capacity - 1 + index];
        }

        pub fn markDirty(self: *Self, leaf_index: usize) void {
            std.debug.assert(leaf_index < self.capacity);
            if (self.dirty_low) |low| {
                self.dirty_low = @min(low, leaf_index);
                self.dirty_high = @max(self.dirty_high.?, leaf_index);
            } else {
                self.dirty_low = leaf_index;
                self.dirty_high = leaf_index;
            }
            self.root_valid = false;
        }

        fn hashPair(self: *Self, parent: usize, left: usize, right: usize) void {
            var hasher = Hasher.init(Hasher.Options{});
            hasher.update(&self.nodes[left]);
            hasher.update(&self.nodes[right]);
            hasher.final(&self.nodes[parent]);
        }

        /// Root of the materialized data subtree (over `capacity` leaves, with
        /// padding leaves already zero). Returns zero_chunk when empty. Only
        /// rehashes the paths from dirty leaves up to the root.
        pub fn recompute(self: *Self) chunk {
            if (self.capacity == 0) return zero_chunk;
            const low_leaf = self.dirty_low orelse return self.nodes[0];
            var low = low_leaf + self.capacity - 1;
            var high = self.dirty_high.? + self.capacity - 1;

            while (low > 0) {
                // Expand the range to whole sibling pairs. The pulled-in sibling
                // is a clean (possibly transplanted) node, read as a valid input
                // without being recomputed.
                const pair_low = if (low % 2 == 1) low else low - 1;
                const pair_high = if (high % 2 == 0) high else high + 1;

                var i = pair_low;
                while (i <= pair_high) : (i += 2) {
                    self.hashPair((i - 1) / 2, i, i + 1);
                }

                low = (pair_low - 1) / 2;
                high = (pair_high - 1) / 2;
            }

            self.dirty_low = null;
            self.dirty_high = null;
            return self.nodes[0];
        }

        /// Full SSZ root: extend the materialized data subtree with zero padding
        /// up to `target_depth`, then mix in the length. Caches the result keyed
        /// by `length`.
        pub fn recomputeWithLength(self: *Self, length: usize, comptime target_depth: usize) chunk {
            comptime std.debug.assert(target_depth <= 64);

            // Hot path: nothing dirtied since the last identical-length root.
            if (self.root_valid and self.cached_length == length) {
                return self.cached_root;
            }

            const data_root = self.recompute();

            // Climb from the materialized depth to the spec depth, hashing the
            // running root against the all-zero subtree at each level.
            const current_depth: usize = if (self.capacity > 0) std.math.log2_int(usize, self.capacity) else 0;
            var current = data_root;
            var level = current_depth;
            while (level < target_depth) : (level += 1) {
                var hasher = Hasher.init(Hasher.Options{});
                hasher.update(&current);
                hasher.update(&hashes_of_zero[level]);
                hasher.final(&current);
            }

            var length_buf: chunk = zero_chunk;
            std.mem.writeInt(u64, length_buf[0..8], @intCast(length), .little);

            var hasher = Hasher.init(Hasher.Options{});
            hasher.update(&current);
            hasher.update(&length_buf);
            hasher.final(&self.cached_root);
            self.cached_length = length;
            self.root_valid = true;
            return self.cached_root;
        }
    };
}

// Tests
fn fillLeaves(comptime Hasher: type, cache: *MerkleCache(Hasher), chunks: []const chunk) void {
    for (chunks, 0..) |c, i| {
        cache.leafPtr(i).* = c;
        cache.markDirty(i);
    }
}

test "MerkleCache.recompute matches merkleize over its capacity" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Cache = MerkleCache(Sha256);

    var cache = Cache.init();
    defer cache.deinit(std.testing.allocator);

    var chunks: [3]chunk = undefined;
    for (0..3) |i| chunks[i] = [_]u8{@intCast(i + 1)} ** 32;
    try cache.ensureCapacity(std.testing.allocator, 3); // capacity -> 4
    fillLeaves(Sha256, &cache, &chunks);
    const root = cache.recompute();

    var expected: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, cache.capacity, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "MerkleCache.recomputeWithLength matches merkleize + mixInLength (limit 8)" {
    const Sha256 = std.crypto.hash.sha2.Sha256;

    var cache = MerkleCache(Sha256).init();
    defer cache.deinit(std.testing.allocator);

    var chunks: [3]chunk = undefined;
    for (0..3) |i| chunks[i] = [_]u8{@intCast(i + 10)} ** 32;
    try cache.ensureCapacity(std.testing.allocator, 3);
    fillLeaves(Sha256, &cache, &chunks);

    const got = cache.recomputeWithLength(3, comptime targetDepth(8));

    var data_root: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 8, &data_root);
    var expected: chunk = undefined;
    lib.mixInLength2(Sha256, data_root, 3, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "MerkleCache empty list matches merkleize empty" {
    const Sha256 = std.crypto.hash.sha2.Sha256;

    var cache = MerkleCache(Sha256).init();
    defer cache.deinit(std.testing.allocator);

    try std.testing.expect(cache.capacity == 0);
    const got = cache.recomputeWithLength(0, comptime targetDepth(4));

    var data_root: chunk = undefined;
    const empty: []chunk = &.{};
    try lib.merkleize(Sha256, empty, 4, &data_root);
    var expected: chunk = undefined;
    lib.mixInLength2(Sha256, data_root, 0, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "MerkleCache incremental update matches full rebuild" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Cache = MerkleCache(Sha256);

    var cache = Cache.init();
    defer cache.deinit(std.testing.allocator);

    var chunks: [4]chunk = undefined;
    for (0..4) |i| chunks[i] = [_]u8{@intCast(i + 1)} ** 32;
    try cache.ensureCapacity(std.testing.allocator, 4);
    fillLeaves(Sha256, &cache, &chunks);
    _ = cache.recompute();

    chunks[2] = [_]u8{0xFF} ** 32;
    cache.leafPtr(2).* = chunks[2];
    cache.markDirty(2);
    const incremental = cache.recompute();

    var expected: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 4, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &incremental);
}

test "MerkleCache grow transplants and reuses the old subtree" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Cache = MerkleCache(Sha256);
    var cache = Cache.init();
    defer cache.deinit(std.testing.allocator);

    const a: chunk = [_]u8{0xA1} ** 32;
    const b: chunk = [_]u8{0xB2} ** 32;
    try cache.ensureCapacity(std.testing.allocator, 2);
    cache.leafPtr(0).* = a;
    cache.markDirty(0);
    cache.leafPtr(1).* = b;
    cache.markDirty(1);
    _ = cache.recompute();

    // Grow to capacity 4. The old leaves must be transplanted, not zeroed, and
    // we must NOT re-set them — only the new leaf gets written.
    try cache.ensureCapacity(std.testing.allocator, 3);
    try std.testing.expect(cache.capacity == 4);
    try std.testing.expectEqualSlices(u8, &a, cache.leafPtr(0));
    try std.testing.expectEqualSlices(u8, &b, cache.leafPtr(1));

    const c: chunk = [_]u8{0xC3} ** 32;
    cache.leafPtr(2).* = c;
    cache.markDirty(2);
    const root = cache.recompute();

    var chunks = [_]chunk{ a, b, c, zero_chunk };
    var expected: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 4, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "MerkleCache multi-level grow reuses interior nodes (k>=2)" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Cache = MerkleCache(Sha256);
    var cache = Cache.init();
    defer cache.deinit(std.testing.allocator);

    const a: chunk = [_]u8{0xA1} ** 32;
    const b: chunk = [_]u8{0xB2} ** 32;
    try cache.ensureCapacity(std.testing.allocator, 2);
    cache.leafPtr(0).* = a;
    cache.markDirty(0);
    cache.leafPtr(1).* = b;
    cache.markDirty(1);
    _ = cache.recompute();

    // Grow 2 -> 8 (k = 2). The old root H(a,b) becomes an *interior* node of the
    // new tree (index 3) and must be reused without rehashing.
    try cache.ensureCapacity(std.testing.allocator, 5);
    try std.testing.expect(cache.capacity == 8);

    // The transplanted interior node holds the old root H(a,b).
    var old_root: chunk = undefined;
    var ab = [_]chunk{ a, b };
    try lib.merkleize(Sha256, &ab, 2, &old_root);
    try std.testing.expectEqualSlices(u8, &old_root, &cache.nodes[3]);

    // Add new data c,d,e without touching the reused leaves 0,1.
    const c: chunk = [_]u8{0xC3} ** 32;
    const d: chunk = [_]u8{0xD4} ** 32;
    const e: chunk = [_]u8{0xE5} ** 32;
    cache.leafPtr(2).* = c;
    cache.markDirty(2);
    cache.leafPtr(3).* = d;
    cache.markDirty(3);
    cache.leafPtr(4).* = e;
    cache.markDirty(4);
    const root = cache.recompute();

    // Interior node still the reused old root; leaves 0,1 still a,b.
    try std.testing.expectEqualSlices(u8, &old_root, &cache.nodes[3]);
    try std.testing.expectEqualSlices(u8, &a, cache.leafPtr(0));
    try std.testing.expectEqualSlices(u8, &b, cache.leafPtr(1));

    var chunks = [_]chunk{ a, b, c, d, e, zero_chunk, zero_chunk, zero_chunk };
    var expected: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 8, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}
