const std = @import("std");
const lib = @import("./lib.zig");

// Zig compiler configuration
const serialize = lib.serialize;
const deserialize = lib.deserialize;
const isFixedSizeObject = lib.isFixedSizeObject;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const sha256 = std.crypto.hash.sha2.Sha256;
const hashes_of_zero = @import("./zeros.zig").hashes_of_zero;

// SSZ specification constants
const BYTES_PER_CHUNK = 32;
const chunk = [BYTES_PER_CHUNK]u8;
const zero_chunk: chunk = [_]u8{0} ** BYTES_PER_CHUNK;

/// Implements the SSZ `List[N]` container.
pub fn List(comptime T: type, comptime N: usize) type {
    // Compile-time check: List[bool, N] is not allowed, use Bitlist[N] instead
    if (T == bool) {
        @compileError("List[bool, N] is not supported. Use Bitlist(" ++ std.fmt.comptimePrint("{}", .{N}) ++ ") instead for boolean lists.");
    }

    return struct {
        const Self = @This();
        const Item = T;
        const Inner = std.BoundedArray(T, N);

        const OFFSET_SIZE = 4;

        inner: Inner,

        pub fn sszEncode(self: *const Self, l: *ArrayList(u8)) !void {
            try serialize([]const Item, self.inner.slice(), l);
        }

        pub fn isFixedSizeObject() bool {
            return false;
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, allocator: ?std.mem.Allocator) !void {
            // BitList[N] or regular List[N]?
            if (Self.Item == bool) {
                @panic("Use the optimized utils.Bitlist(N) instead of utils.List(bool, N)");
            } else if (try lib.isFixedSizeObject(Self.Item)) {
                const pitch = try lib.serializedFixedSize(Self.Item);
                const n_items = serialized.len / pitch;

                // Validate list size against maximum N
                if (n_items > N) {
                    return error.ListTooBig;
                }

                for (0..n_items) |i| {
                    var item: Self.Item = undefined;
                    try deserialize(Self.Item, serialized[i * pitch .. (i + 1) * pitch], &item, allocator);
                    try out.append(item);
                }
            } else {
                // Validate and decode dynamic list length
                const size = try Self.decodeDynamicLength(serialized);

                const indices = std.mem.bytesAsSlice(u32, serialized[0 .. size * 4]);
                var i = @as(usize, 0);
                while (i < size) : (i += 1) {
                    const end = if (i < size - 1) indices[i + 1] else serialized.len;
                    const start = indices[i];
                    if (start >= serialized.len or end > serialized.len) {
                        return error.OffsetExceedsSize;
                    }
                    if (i > 0 and start < indices[i - 1]) {
                        return error.OffsetOrdering;
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

        pub fn len(self: *const Self) usize {
            return self.inner.len;
        }

        pub fn serializedSize(self: *const Self) !usize {
            const inner_slice = self.inner.constSlice();
            return lib.serializedSize(@TypeOf(inner_slice), inner_slice);
        }

        pub fn hashTreeRoot(self: *const Self, out: *[32]u8, allctr: Allocator) !void {
            const items = self.constSlice();

            if (items.len == 0) {
                const tmp: chunk = zero_chunk;
                lib.mixInLength2(tmp, 0, out);
                return;
            }

            switch (@typeInfo(Item)) {
                .int => {
                    var list = ArrayList(u8).init(allctr);
                    defer list.deinit();
                    const chunks = try lib.pack([]const Item, items, &list);

                    const bytes_per_item = @sizeOf(Item);
                    const items_per_chunk = BYTES_PER_CHUNK / bytes_per_item;
                    const chunks_for_max_capacity = (N + items_per_chunk - 1) / items_per_chunk;
                    var tmp: chunk = undefined;
                    try lib.merkleize(sha256, chunks, chunks_for_max_capacity, &tmp);
                    lib.mixInLength2(tmp, items.len, out);
                },
                else => {
                    var chunks = ArrayList(chunk).init(allctr);
                    defer chunks.deinit();
                    var tmp: chunk = undefined;
                    for (items) |item| {
                        try lib.hashTreeRoot(Item, item, &tmp, allctr);
                        try chunks.append(tmp);
                    }
                    try lib.merkleize(sha256, chunks.items, N, &tmp);
                    lib.mixInLength2(tmp, items.len, out);
                },
            }
        }

        /// Decodes and validates the length from dynamic input
        pub fn decodeDynamicLength(buf: []const u8) !u32 {
            if (buf.len == 0) {
                return 0;
            }
            if (buf.len < 4) {
                return error.DynamicLengthTooShort;
            }

            const offset = std.mem.readInt(u32, buf[0..4], std.builtin.Endian.little);
            if (offset % OFFSET_SIZE != 0 or offset == 0) {
                return error.DynamicLengthNotOffsetSized;
            }

            const length = offset / OFFSET_SIZE;
            if (length > N) {
                return error.DynamicLengthExceedsMax;
            }

            return length;
        }
    };
}

/// Implements the SSZ `Bitlist[N]` container
pub fn Bitlist(comptime N: usize) type {
    return struct {
        const Self = @This();
        const Inner = std.BoundedArray(u8, (N + 7) / 8);

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

            // Comprehensive validation (handles empty, trailing zero, size limits)
            try Self.validateBitlist(serialized);

            // If validation passed but buffer is empty, we're done
            if (serialized.len == 0) {
                return;
            }

            // Parse the bit structure (validation already confirmed it's valid)
            const byte_len = serialized.len - 1;
            var last_byte = serialized[byte_len];
            var bit_len: usize = 8;
            while (last_byte & @shlExact(@as(usize, 1), @truncate(bit_len)) == 0) : (bit_len -= 1) {}

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

        pub fn isFixedSizeObject() bool {
            return false;
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

        pub fn len(self: *const Self) usize {
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

        pub fn hashTreeRoot(self: *const Self, out: *[32]u8, allctr: Allocator) !void {
            const bit_length = self.length;
            if (bit_length == 0) {
                const tmp: chunk = zero_chunk;
                lib.mixInLength2(tmp, 0, out);
                return;
            }

            var list = ArrayList(u8).init(allctr);
            defer list.deinit();

            const byte_slice = self.inner.constSlice();
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
            try lib.merkleize(sha256, chunks, null, &tmp);
            lib.mixInLength2(tmp, bit_length, out);
        }

        /// Validates that the bitlist is correctly formed
        pub fn validateBitlist(buf: []const u8) !void {
            const byte_len = buf.len;
            if (byte_len == 0) return;

            // Maximum possible bytes in a bitlist with provided bitlimit.
            const max_bytes = (N >> 3) + 1;
            if (byte_len > max_bytes) {
                return error.BitlistTooManyBytes;
            }

            // The most significant bit is present in the last byte in the array.
            const last = buf[byte_len - 1];
            if (last == 0) {
                return error.BitlistTrailingByteZero;
            }

            // Determine the position of the most significant bit.
            // Find most significant bit position
            const msb_pos = if (last == 0) 0 else 8 - @clz(last);

            // The absolute position of the most significant bit will be the number of
            // bits in the preceding bytes plus the position of the most significant
            // bit. Subtract this value by 1 to determine the length of the bitlist.
            const num_of_bits: u64 = @intCast(8 * (byte_len - 1) + msb_pos - 1);

            if (num_of_bits > N) {
                return error.BitlistTooManyBits;
            }
        }
    };
}
