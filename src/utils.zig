const std = @import("std");
const lib = @import("./lib.zig");
const serialize = lib.serialize;
const deserialize = lib.deserialize;
const isFixedSizeObject = lib.isFixedSizeObject;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const sha256 = std.crypto.hash.sha2.Sha256;
const hashes_of_zero = @import("./zeros.zig").hashes_of_zero;

// SSZ specification constants
const BYTES_PER_CHUNK = lib.BYTES_PER_CHUNK;
const chunk = lib.chunk;
const zero_chunk = lib.zero_chunk;

/// Returns true if the type is a utils.List type
pub fn isListType(comptime T: type) bool {
    if (@typeInfo(T) != .@"struct") return false;

    // Primary: check for explicit SSZ type marker
    if (@hasDecl(T, "ssz_type_kind")) {
        return T.ssz_type_kind == .list;
    }

    // Fallback: structural check
    return @hasField(T, "inner") and
        std.meta.hasFn(T, "sszEncode") and
        std.meta.hasFn(T, "sszDecode") and
        std.meta.hasFn(T, "append") and
        std.meta.hasFn(T, "slice") and
        !@hasField(T, "length");
}

/// Returns true if the type is a utils.Bitlist type
pub fn isBitlistType(comptime T: type) bool {
    if (@typeInfo(T) != .@"struct") return false;

    // Primary: check for explicit SSZ type marker
    if (@hasDecl(T, "ssz_type_kind")) {
        return T.ssz_type_kind == .bitlist;
    }

    // Fallback: structural check
    return @hasField(T, "inner") and
        @hasField(T, "length") and
        std.meta.hasFn(T, "sszEncode") and
        std.meta.hasFn(T, "sszDecode") and
        std.meta.hasFn(T, "get") and
        std.meta.hasFn(T, "set");
}

/// Implements the SSZ `List[N]` container.
pub fn List(comptime T: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        const Item = T;
        const Inner = std.BoundedArray(T, N);
        const ssz_type_kind = .list;

        inner: Inner,

        pub fn sszEncode(self: *const Self, l: *ArrayList(u8)) !void {
            try serialize([]const Item, self.inner.slice(), l);
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, allocator: ?std.mem.Allocator) !void {
            // BitList[N] or regular List[N]?
            if (Self.Item == bool) {
                @panic("Use the optimized utils.Bitlist(N) instead of utils.List(bool, N)");
            } else if (try isFixedSizeObject(Self.Item)) {
                const pitch = try lib.serializedSize(Self.Item, undefined);
                const n_items = serialized.len / pitch;
                for (0..n_items) |i| {
                    var item: Self.Item = undefined;
                    try deserialize(Self.Item, serialized[i * pitch .. (i + 1) * pitch], &item, allocator);
                    try out.append(item);
                }
            } else {
                // first variable index is also the size of the list
                // of indices. Recast that list as a []const u32.
                const size = std.mem.readInt(u32, serialized[0..4], std.builtin.Endian.little) / @sizeOf(u32);
                const indices = std.mem.bytesAsSlice(u32, serialized[0 .. size * 4]);
                var i = @as(usize, 0);
                while (i < size) : (i += 1) {
                    const end = if (i < size - 1) indices[i + 1] else serialized.len;
                    const start = indices[i];
                    if (start >= serialized.len or end > serialized.len) {
                        return error.IndexOutOfBounds;
                    }
                    const item = try out.inner.addOne();
                    try deserialize(Self.Item, serialized[start..end], item, allocator);
                }
            }
        }

        pub fn init(length: usize) error{Overflow}!Self {
            return .{ .inner = try Inner.init(length) };
        }

        pub fn eql(self: *const Self, other: *Self) bool {
            return (self.inner.len == other.inner.len) and std.mem.eql(Self.Item, self.inner.constSlice()[0..self.inner.len], other.inner.constSlice()[0..other.inner.len]);
        }

        pub fn append(self: *Self, item: Self.Item) error{Overflow}!void {
            return self.inner.append(item);
        }

        pub fn slice(self: *Self) []T {
            return self.inner.slice();
        }

        pub fn constSlice(self: *const Self) []const T {
            return self.inner.constSlice();
        }

        pub fn fromSlice(m: []const T) error{Overflow}!Self {
            return .{ .inner = try Inner.fromSlice(m) };
        }

        pub fn get(self: Self, i: usize) T {
            return self.inner.get(i);
        }

        pub fn set(self: *Self, i: usize, item: T) void {
            self.inner.set(i, item);
        }

        pub fn len(self: *Self) usize {
            return self.inner.len;
        }

        pub fn serializedSize(self: *const Self) !usize {
            const inner_slice = self.inner.constSlice();
            return lib.serializedSize(@TypeOf(inner_slice), inner_slice);
        }
    };
}

/// Implements the SSZ `Bitlist[N]` container
pub fn Bitlist(comptime N: usize) type {
    return struct {
        const Self = @This();
        const Inner = std.BoundedArray(u8, (N + 7) / 8);
        const ssz_type_kind = .bitlist;

        inner: Inner,
        length: usize,

        pub fn sszEncode(self: *const Self, l: *ArrayList(u8)) !void {
            if (self.length == 0) {
                return;
            }

            // slice has at least one byte, appends all
            // non-terminal bytes.
            const slice = self.inner.constSlice();
            try l.appendSlice(slice[0 .. slice.len - 1]);

            try l.append(slice[slice.len - 1] | @shlExact(@as(u8, 1), @truncate(self.length % 8)));
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, _: ?std.mem.Allocator) !void {
            out.* = try init(0);
            if (serialized.len == 0) {
                return;
            }

            // determine where the last bit is
            const byte_len = serialized.len - 1;
            var last_byte = serialized[byte_len];
            var bit_len: usize = 8;
            if (last_byte == 0) {
                return error.InvalidEncoding;
            }
            while (last_byte & @shlExact(@as(usize, 1), @truncate(bit_len)) == 0) : (bit_len -= 1) {}
            if (bit_len + 8 * byte_len > N) {
                return error.InvalidEncoding;
            }

            // insert all full bytes
            try out.*.inner.insertSlice(0, serialized[0..byte_len]);
            out.*.length = 8 * byte_len;

            // insert last bits
            last_byte = serialized[byte_len];
            for (0..bit_len) |_| {
                try out.*.append(last_byte & 1 == 1);
                last_byte >>= 1;
            }
        }

        pub fn init(length: usize) error{Overflow}!Self {
            return .{ .inner = try Inner.init((length + 7) / 8), .length = length };
        }

        pub fn get(self: Self, i: usize) bool {
            if (i >= self.length) {
                var buf: [1024]u8 = undefined;
                const str = std.fmt.bufPrint(&buf, "out of bounds: want index {}, len {}", .{ i, self.length }) catch unreachable;
                @panic(str);
            }
            return self.inner.get(i / 8) & @shlExact(@as(u8, 1), @truncate(i % 8)) != 0;
        }

        pub fn set(self: *Self, i: usize, bit: bool) void {
            const mask = ~@shlExact(@as(u8, 1), @truncate(i % 8));
            const b = if (bit) @shlExact(@as(u8, 1), @truncate(i % 8)) else 0;
            self.inner.set(i / 8, @truncate((self.inner.get(i / 8) & mask) | b));
        }

        pub fn append(self: *Self, item: bool) error{Overflow}!void {
            if (self.length % 8 == 7 or self.length == 0) {
                try self.inner.append(0);
            }
            self.length += 1;
            self.set(self.length - 1, item);
        }

        pub fn len(self: *Self) usize {
            return if (self.length > N) N else self.length;
        }

        pub fn eql(self: *const Self, other: *Self) bool {
            return (self.length == other.length) and std.mem.eql(u8, self.inner.constSlice()[0..self.inner.len], other.inner.constSlice()[0..other.inner.len]);
        }

        pub fn serializedSize(self: *const Self) usize {
            if (self.length == 0) return 0;
            // Size is number of bytes needed plus one bit for the sentinel
            return (self.length + 7) / 8;
        }
    };
}
pub fn mixInLength2(root: [32]u8, length: usize, out: *[32]u8) void {
    var hasher = sha256.init(sha256.Options{});
    hasher.update(root[0..]);

    var tmp = [_]u8{0} ** 32;
    std.mem.writeInt(@TypeOf(length), tmp[0..@sizeOf(@TypeOf(length))], length, std.builtin.Endian.little);
    hasher.update(tmp[0..]);
    hasher.final(out[0..]);
}

pub fn pack(comptime T: type, values: T, l: *ArrayList(u8)) ![]chunk {
    try serialize(T, values, l);
    const padding_size = (BYTES_PER_CHUNK - l.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
    _ = try l.writer().write(zero_chunk[0..padding_size]);
    return std.mem.bytesAsSlice(chunk, l.items);
}

// merkleize recursively calculates the root hash of a Merkle tree.
pub fn merkleize(hasher: type, chunks: []chunk, limit: ?usize, out: *[32]u8) anyerror!void {
    // Calculate the number of chunks to be padded, check the limit
    if (limit != null and chunks.len > limit.?) {
        return error.ChunkSizeExceedsLimit;
    }
    const power = limit orelse chunks.len;
    const size = if (power > 0) try std.math.ceilPowerOfTwo(usize, power) else 0;

    // Perform the merkelization
    switch (size) {
        0 => std.mem.copyForwards(u8, out.*[0..], zero_chunk[0..]),
        1 => std.mem.copyForwards(u8, out.*[0..], chunks[0][0..]),
        else => {
            // Merkleize the left side. If the number of chunks
            // isn't enough to fill the entire width, complete
            // with zeroes.
            var digest = hasher.init(hasher.Options{});
            var buf: [32]u8 = undefined;
            const split = if (size / 2 < chunks.len) size / 2 else chunks.len;
            try merkleize(hasher, chunks[0..split], size / 2, &buf);
            digest.update(buf[0..]);

            // Merkleize the right side. If the number of chunks only
            // covers the first half, directly input the hashed zero-
            // filled subtrie.
            if (size / 2 < chunks.len) {
                try merkleize(hasher, chunks[size / 2 ..], size / 2, &buf);
                digest.update(buf[0..]);
            } else digest.update(hashes_of_zero[size / 2 - 1][0..]);
            digest.final(out);
        },
    }
}

/// Specialized hash tree root function for List types
/// Implements the required mix_in_length operation for variable-length containers
pub fn hashTreeRootList(comptime T: type, value: T, out: *[32]u8, allctr: Allocator) !void {
    const slice = value.constSlice();

    if (slice.len == 0) {
        const tmp: chunk = zero_chunk;
        mixInLength2(tmp, 0, out);
        return;
    }

    const Item = T.Item;
    switch (@typeInfo(Item)) {
        .int => {
            var list = ArrayList(u8).init(allctr);
            defer list.deinit();
            const chunks = try pack([]const Item, slice, &list);
            var tmp: chunk = undefined;
            try merkleize(sha256, chunks, null, &tmp);
            mixInLength2(tmp, slice.len, out);
        },
        else => {
            var chunks = ArrayList(chunk).init(allctr);
            defer chunks.deinit();
            var tmp: chunk = undefined;
            for (slice) |item| {
                try lib.hashTreeRoot(Item, item, &tmp, allctr);
                try chunks.append(tmp);
            }
            try merkleize(sha256, chunks.items, null, &tmp);
            mixInLength2(tmp, slice.len, out);
        },
    }
}

/// Specialized hash tree root function for Bitlist types
/// Implements the required mix_in_length operation for variable-length containers
pub fn hashTreeRootBitlist(comptime T: type, value: T, out: *[32]u8, allctr: Allocator) !void {
    const bit_length = value.length;
    if (bit_length == 0) {
        const tmp: chunk = zero_chunk;
        mixInLength2(tmp, 0, out);
        return;
    }

    var list = ArrayList(u8).init(allctr);
    defer list.deinit();

    const byte_slice = value.inner.constSlice();
    const full_bytes = bit_length / 8;
    const remaining_bits = bit_length % 8;

    if (full_bytes > 0) {
        try list.appendSlice(byte_slice[0..full_bytes]);
    }

    if (remaining_bits > 0) {
        const last_byte = byte_slice[full_bytes];
        const mask = (@as(u8, 1) << @truncate(remaining_bits)) - 1;
        try list.append(last_byte & mask);
    }

    const padding_size = (BYTES_PER_CHUNK - list.items.len % BYTES_PER_CHUNK) % BYTES_PER_CHUNK;
    _ = try list.writer().write(zero_chunk[0..padding_size]);

    const chunks = std.mem.bytesAsSlice(chunk, list.items);
    var tmp: chunk = undefined;
    try merkleize(sha256, chunks, null, &tmp);
    mixInLength2(tmp, bit_length, out);
}

test "pack u32" {
    var expected: [32]u8 = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const out = try pack(u32, 0xdeadbeef, &list);

    _ = try std.fmt.hexToBytes(expected[0..], "efbeadde00000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..]));
}

test "pack bool" {
    var expected: [32]u8 = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const out = try pack(bool, true, &list);

    _ = try std.fmt.hexToBytes(expected[0..], "0100000000000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..]));
}

test "pack string" {
    var expected: [128]u8 = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const out = try pack([]const u8, "a" ** 100, &list);

    _ = try std.fmt.hexToBytes(expected[0..], "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000000000000000000000000000000000000000000000000000000");

    try std.testing.expect(expected.len == out.len * out[0].len);
    try std.testing.expect(std.mem.eql(u8, out[0][0..], expected[0..32]));
    try std.testing.expect(std.mem.eql(u8, out[1][0..], expected[32..64]));
    try std.testing.expect(std.mem.eql(u8, out[2][0..], expected[64..96]));
    try std.testing.expect(std.mem.eql(u8, out[3][0..], expected[96..]));
}

test "merkleize an empty slice" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const chunks = &[0][32]u8{};
    var out: [32]u8 = undefined;
    try merkleize(sha256, chunks, null, &out);
    try std.testing.expect(std.mem.eql(u8, out[0..], zero_chunk[0..]));
}

test "merkleize a string" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const chunks = try pack([]const u8, "a" ** 100, &list);
    var out: [32]u8 = undefined;
    try merkleize(sha256, chunks, null, &out);
    // Build the expected tree
    const leaf1 = [_]u8{0x61} ** 32; // "0xaaaaa....aa" 32 times
    var leaf2: [32]u8 = [_]u8{0x61} ** 4 ++ [_]u8{0} ** 28;
    var root: [32]u8 = undefined;
    var internal_left: [32]u8 = undefined;
    var internal_right: [32]u8 = undefined;
    var hasher = sha256.init(sha256.Options{});
    hasher.update(leaf1[0..]);
    hasher.update(leaf1[0..]);
    hasher.final(&internal_left);
    hasher = sha256.init(sha256.Options{});
    hasher.update(leaf1[0..]);
    hasher.update(leaf2[0..]);
    hasher.final(&internal_right);
    hasher = sha256.init(sha256.Options{});
    hasher.update(internal_left[0..]);
    hasher.update(internal_right[0..]);
    hasher.final(&root);

    try std.testing.expect(std.mem.eql(u8, out[0..], root[0..]));
}

test "merkleize a boolean" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    var chunks = try pack(bool, false, &list);
    var expected = [_]u8{0} ** BYTES_PER_CHUNK;
    var out: [BYTES_PER_CHUNK]u8 = undefined;
    try merkleize(sha256, chunks, null, &out);

    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();

    chunks = try pack(bool, true, &list2);
    expected[0] = 1;
    try merkleize(sha256, chunks, null, &out);
    try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));
}

test "merkleize a bytes16 vector with one element" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    _ = try pack([16]u8, [_]u8{0xaa} ** 16, &list);
    // var expected: [32]u8 = [_]u8{0xaa} ** 16 ++ [_]u8{0x00} ** 16;
    // var out: [32]u8 = undefined;
    // try merkleize(sha256, chunks, null, &out);
    // try std.testing.expect(std.mem.eql(u8, out[0..], expected[0..]));
}
