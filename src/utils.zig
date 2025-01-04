const std = @import("std");
const lib = @import("./lib.zig");
const serialize = lib.serialize;
const deserialize = lib.deserialize;
const isFixedSizeObject = lib.isFixedSizeObject;
const ArrayList = std.ArrayList;

/// Implements the SSZ `List[N]` container.
pub fn List(comptime T: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        const Item = T;
        const Inner = std.BoundedArray(T, N);

        inner: Inner,

        pub fn sszEncode(self: *const Self, l: *ArrayList(u8)) !void {
            try serialize([]const Item, self.inner.slice(), l);
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, allocator: ?std.mem.Allocator) !void {
            // BitList[N] or regular List[N]?
            if (Self.Item == bool) {
                for (serialized, 0..) |byte, bindex| {
                    var i = @as(u8, 0);
                    var b = byte;
                    while (bindex * 8 + i < out.len and i < 8) : (i += 1) {
                        out[bindex * 8 + i] = b & 1 == 1;
                        b >>= 1;
                    }
                }
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
            return .{ .inner = try std.BoundedArray(T, N).init(length) };
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
    };
}

pub fn Bitlist(comptime N: usize) type {
    return List(bool, N);
}
