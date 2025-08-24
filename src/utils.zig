const std = @import("std");
const lib = @import("./lib.zig");
const serialize = lib.serialize;
const deserialize = lib.deserialize;
const isFixedSizeObject = lib.isFixedSizeObject;
const ArrayList = std.ArrayList;

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
            return (self.length + 8) / 8;
        }
    };
}
