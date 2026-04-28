const std = @import("std");
const zeros = @import("./zeros.zig");

const BYTES_PER_CHUNK = 32;
const chunk = [BYTES_PER_CHUNK]u8;
const zero_chunk: chunk = [_]u8{0} ** BYTES_PER_CHUNK;

/// A cached Merkle tree using a flat 1-indexed array representation.
/// Node 1 is the root. Node i has children 2i and 2i+1.
/// Leaves occupy indices [capacity .. 2*capacity).
pub fn MerkleCache(comptime Hasher: type) type {
    return struct {
        const Self = @This();
        const hashes_of_zero = zeros.buildHashesOfZero(Hasher, 32, 256);

        /// Flat array of tree nodes, 1-indexed. Length = 2 * capacity.
        /// Index 0 is unused. nodes[1] = root. nodes[capacity..2*capacity] = leaves.
        nodes: []chunk,
        /// Number of leaf slots (next power of 2 of the limit).
        capacity: usize,
        /// Dirty leaf range (0-based, relative to leaf start).
        /// dirty_low > dirty_high means no dirty leaves.
        dirty_low: usize,
        dirty_high: usize,
        /// Whether the full tree has been computed at least once.
        initialized: bool,
        /// Cached length for mixInLength detection.
        cached_length: usize,
        /// Final root after mixInLength.
        cached_root: chunk,
        /// Whether cached_root is valid.
        root_valid: bool,

        pub fn init(allocator: std.mem.Allocator, limit: usize) !Self {
            const capacity = if (limit > 0) try std.math.ceilPowerOfTwo(usize, limit) else 1;
            const nodes = try allocator.alloc([BYTES_PER_CHUNK]u8, 2 * capacity);
            @memset(nodes, zero_chunk);
            return .{
                .nodes = nodes,
                .capacity = capacity,
                .dirty_low = 0,
                .dirty_high = 0,
                .initialized = false,
                .cached_length = 0,
                .cached_root = zero_chunk,
                .root_valid = false,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.nodes);
        }

        pub fn markDirty(self: *Self, leaf_index: usize) void {
            if (self.dirty_low > self.dirty_high) {
                // Currently clean — set range to single leaf
                self.dirty_low = leaf_index;
                self.dirty_high = leaf_index;
            } else {
                if (leaf_index < self.dirty_low) self.dirty_low = leaf_index;
                if (leaf_index > self.dirty_high) self.dirty_high = leaf_index;
            }
            self.root_valid = false;
        }

        pub fn markAllDirty(self: *Self) void {
            self.dirty_low = 0;
            self.dirty_high = self.capacity - 1;
            self.root_valid = false;
        }

        /// Mark clean (dirty_low > dirty_high).
        fn markClean(self: *Self) void {
            self.dirty_low = 1;
            self.dirty_high = 0;
        }

        /// Set a leaf chunk value and mark it dirty.
        pub fn setLeaf(self: *Self, index: usize, value: chunk) void {
            self.nodes[self.capacity + index] = value;
            self.markDirty(index);
        }

        /// Recompute the Merkle root, only rehashing dirty paths.
        /// `num_chunks` is the number of actual data chunks (rest are zero-padded).
        /// Returns the data root (before mixInLength).
        pub fn recompute(self: *Self, num_chunks: usize) chunk {
            if (!self.initialized) {
                // First time: set all leaves beyond data to zero, hash everything bottom-up
                for (num_chunks..self.capacity) |i| {
                    self.nodes[self.capacity + i] = zero_chunk;
                }
                // Hash all internal nodes bottom-up
                var level_size = self.capacity;
                while (level_size > 1) : (level_size /= 2) {
                    const level_start = level_size; // start index of this level
                    var i = level_start;
                    while (i < level_start + level_size) : (i += 2) {
                        self.hashPair(i / 2, i, i + 1);
                    }
                }
                self.initialized = true;
                self.markClean();
                return self.nodes[1];
            }

            // If nothing is dirty, return cached root
            if (self.dirty_low > self.dirty_high) {
                return self.nodes[1];
            }

            // Incremental update: rehash only dirty paths
            // Start at leaf level, process dirty range, then walk up
            var lo = self.dirty_low + self.capacity;
            var hi = self.dirty_high + self.capacity;

            // Ensure parents of the dirty range are rehashed at each level
            while (lo > 1) {
                // Align to pairs: we need to hash the parent of each node in [lo, hi]
                const pair_lo = lo - (lo % 2); // round down to even (left sibling)
                const pair_hi = hi + 1 - (hi % 2); // round up to odd (right sibling)

                var i = pair_lo;
                while (i < pair_hi) : (i += 2) {
                    self.hashPair(i / 2, i, i + 1);
                }

                // Move to parent level
                lo = pair_lo / 2;
                hi = pair_hi / 2;
            }

            self.markClean();
            return self.nodes[1];
        }

        fn hashPair(self: *Self, parent: usize, left: usize, right: usize) void {
            var hasher = Hasher.init(Hasher.Options{});
            hasher.update(&self.nodes[left]);
            hasher.update(&self.nodes[right]);
            hasher.final(&self.nodes[parent]);
        }

        /// Convenience: compute root with mixInLength applied.
        pub fn recomputeWithLength(self: *Self, num_chunks: usize, length: usize) chunk {
            const data_root = self.recompute(num_chunks);

            if (self.root_valid and self.cached_length == length) {
                return self.cached_root;
            }

            // Apply mixInLength
            var length_buf: chunk = zero_chunk;
            std.mem.writeInt(u64, length_buf[0..8], @intCast(length), .little);

            var hasher = Hasher.init(Hasher.Options{});
            hasher.update(&data_root);
            hasher.update(&length_buf);
            hasher.final(&self.cached_root);
            self.cached_length = length;
            self.root_valid = true;
            return self.cached_root;
        }
    };
}

// Tests
const Sha256 = std.crypto.hash.sha2.Sha256;
const lib = @import("./lib.zig");

test "MerkleCache produces same root as merkleize for single chunk" {
    const cache_type = MerkleCache(Sha256);
    var cache = try cache_type.init(std.testing.allocator, 1);
    defer cache.deinit(std.testing.allocator);

    const data: chunk = [_]u8{0xAB} ** 32;
    cache.setLeaf(0, data);

    const cached_root = cache.recompute(1);

    var expected: chunk = undefined;
    var chunks = [_]chunk{data};
    try lib.merkleize(Sha256, &chunks, 1, &expected);

    try std.testing.expectEqualSlices(u8, &expected, &cached_root);
}

test "MerkleCache produces same root as merkleize for multiple chunks" {
    const cache_type = MerkleCache(Sha256);
    var cache = try cache_type.init(std.testing.allocator, 4);
    defer cache.deinit(std.testing.allocator);

    var chunks: [3]chunk = undefined;
    for (0..3) |i| {
        const byte: u8 = @intCast(i + 1);
        chunks[i] = [_]u8{byte} ** 32;
        cache.setLeaf(i, chunks[i]);
    }

    const cached_root = cache.recompute(3);

    var expected: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 4, &expected);

    try std.testing.expectEqualSlices(u8, &expected, &cached_root);
}

test "MerkleCache incremental update matches full rebuild" {
    const cache_type = MerkleCache(Sha256);
    var cache = try cache_type.init(std.testing.allocator, 4);
    defer cache.deinit(std.testing.allocator);

    // Initial build with 4 chunks
    var chunks: [4]chunk = undefined;
    for (0..4) |i| {
        const byte: u8 = @intCast(i + 1);
        chunks[i] = [_]u8{byte} ** 32;
        cache.setLeaf(i, chunks[i]);
    }
    _ = cache.recompute(4);

    // Modify one chunk and recompute incrementally
    chunks[2] = [_]u8{0xFF} ** 32;
    cache.setLeaf(2, chunks[2]);
    const incremental_root = cache.recompute(4);

    // Full rebuild for comparison
    var expected: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 4, &expected);

    try std.testing.expectEqualSlices(u8, &expected, &incremental_root);
}

test "MerkleCache recomputeWithLength matches merkleize + mixInLength" {
    const cache_type = MerkleCache(Sha256);
    var cache = try cache_type.init(std.testing.allocator, 8);
    defer cache.deinit(std.testing.allocator);

    var chunks: [3]chunk = undefined;
    for (0..3) |i| {
        const byte: u8 = @intCast(i + 10);
        chunks[i] = [_]u8{byte} ** 32;
        cache.setLeaf(i, chunks[i]);
    }

    const cached = cache.recomputeWithLength(3, 3);

    // Compare: merkleize then mixInLength2
    var data_root: chunk = undefined;
    try lib.merkleize(Sha256, &chunks, 8, &data_root);
    var expected: chunk = undefined;
    lib.mixInLength2(Sha256, data_root, 3, &expected);

    try std.testing.expectEqualSlices(u8, &expected, &cached);
}

test "MerkleCache empty chunks" {
    const cache_type = MerkleCache(Sha256);
    var cache = try cache_type.init(std.testing.allocator, 4);
    defer cache.deinit(std.testing.allocator);

    // No leaves set — all zeros
    const cached_root = cache.recompute(0);

    var expected: chunk = undefined;
    const empty: []chunk = &.{};
    try lib.merkleize(Sha256, empty, 4, &expected);

    try std.testing.expectEqualSlices(u8, &expected, &cached_root);
}
