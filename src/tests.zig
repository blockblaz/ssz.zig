const libssz = @import("ssz.zig");
const utils = libssz.utils;
const serialize = libssz.serialize;
const deserialize = libssz.deserialize;
const serializedSize = libssz.serializedSize;
const chunkCount = libssz.chunkCount;
const hashTreeRoot = libssz.hashTreeRoot;
const isFixedSizeObject = libssz.isFixedSizeObject;
const std = @import("std");
const ArrayList = std.ArrayList;
const expect = std.testing.expect;
const sha256 = std.crypto.hash.sha2.Sha256;

test "serializes uint8" {
    const data: u8 = 0x55;
    const serialized_data = [_]u8{0x55};

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u8, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "serializes uint16" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u16, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "serializes uint32" {
    const data: u32 = 0x55667788;
    const serialized_data = [_]u8{ 0x88, 0x77, 0x66, 0x55 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u32, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "serializes a int32" {
    const data: i32 = -(0x11223344);
    const serialized_data = [_]u8{ 0xbc, 0xcc, 0xdd, 0xee };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(i32, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "non-byte aligned int serialization fails" {
    const data: u10 = 0x03ff;
    var list = ArrayList(u8).init(std.testing.allocator);
    try std.testing.expectError(error.InvalidSerializedIntLengthType, serialize(u10, data, &list));
}

test "serializes bool" {
    var data = false;
    var serialized_data = [_]u8{0x00};

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(bool, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));

    data = true;
    serialized_data = [_]u8{0x01};

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();
    try serialize(bool, data, &list2);
    try expect(std.mem.eql(u8, list2.items, serialized_data[0..]));
}

test "serializes Bitvector[N] == [N]bool" {
    const data7 = [_]bool{ true, false, true, true, false, false, false };
    var serialized_data = [_]u8{0b00001101};
    var exp = serialized_data[0..serialized_data.len];

    var list7 = ArrayList(u8).init(std.testing.allocator);
    defer list7.deinit();
    try serialize([7]bool, data7, &list7);
    try expect(std.mem.eql(u8, list7.items, exp));

    const data8 = [_]bool{ true, false, true, true, false, false, false, true };
    serialized_data = [_]u8{0b10001101};
    exp = serialized_data[0..serialized_data.len];

    var list8 = ArrayList(u8).init(std.testing.allocator);
    defer list8.deinit();
    try serialize([8]bool, data8, &list8);
    try expect(std.mem.eql(u8, list8.items, exp));

    const data12 = [_]bool{ true, false, true, true, false, false, false, true, false, true, false, true };

    var list12 = ArrayList(u8).init(std.testing.allocator);
    defer list12.deinit();
    try serialize([12]bool, data12, &list12);
    try expect(list12.items.len == 2);
    try expect(list12.items[0] == 141);
    try expect(list12.items[1] == 10);
}

test "serializes string" {
    const data = "zig zag";

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u8, data, &list);
    try expect(std.mem.eql(u8, list.items, data));
}

test "serializes an array of shorts" {
    const data = [_]u16{ 0xabcd, 0xef01 };
    const serialized = [_]u8{ 0xcd, 0xab, 0x01, 0xef };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u16, data[0..data.len], &list);
    try expect(std.mem.eql(u8, list.items, serialized[0..]));
}

test "serializes an array of structures" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const exp = [_]u8{ 8, 0, 0, 0, 23, 0, 0, 0, 6, 0, 0, 0, 20, 0, 99, 114, 111, 105, 115, 115, 97, 110, 116, 6, 0, 0, 0, 244, 1, 72, 101, 114, 114, 101, 110, 116, 111, 114, 116, 101 };

    try serialize(@TypeOf(pastries), pastries, &list);
    try expect(std.mem.eql(u8, list.items, exp[0..]));
}

test "serializes a structure without variable fields" {
    const data = .{
        .uint8 = @as(u8, 1),
        .uint32 = @as(u32, 3),
        .boolean = true,
    };
    const serialized_data = [_]u8{ 1, 3, 0, 0, 0, 1 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(data), data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "(de)serializes a structure with variable fields" {
    // Taken from ssz.cr
    const Person = struct {
        name: []const u8,
        age: u8,
        company: []const u8,
    };
    var data = Person{
        .name = "James",
        .age = 32,
        .company = "DEV Inc.",
    };
    const serialized_data = [_]u8{ 9, 0, 0, 0, 32, 14, 0, 0, 0, 74, 97, 109, 101, 115, 68, 69, 86, 32, 73, 110, 99, 46 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    // Note the `&data` - this is so that `data` is not considered const.
    try serialize(@TypeOf(&data), &data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
    var out: @TypeOf(data) = undefined;
    try deserialize(@TypeOf(data), list.items, &out, null);
}

test "serializes a structure with optional fields" {
    const Employee = struct {
        name: ?[]const u8,
        age: u8,
        company: ?[]const u8,
    };
    const data: Employee = .{
        .name = "James",
        .age = @as(u8, 32),
        .company = null,
    };

    const serialized_data = [_]u8{ 9, 0, 0, 0, 32, 15, 0, 0, 0, 1, 74, 97, 109, 101, 115, 0 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(data), data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));

    var deserialized: Employee = undefined;
    try deserialize(Employee, list.items, &deserialized, null);
    // only available in >=0.11
    // try std.testing.expectEqualDeep(data, deserialized);
    try expect(std.mem.eql(u8, data.name.?, deserialized.name.?));
    try std.testing.expectEqual(data.age, deserialized.age);
    try std.testing.expectEqual(deserialized.company, null);
}

test "serializes an optional object" {
    const null_or_string: ?[]const u8 = null;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(null_or_string), null_or_string, &list);
    try expect(list.items.len == 1);
}

test "serializes a union" {
    const Payload = union(enum) {
        int: u64,
        boolean: bool,
    };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const exp = [_]u8{ 0, 210, 4, 0, 0, 0, 0, 0, 0 };
    try serialize(Payload, Payload{ .int = 1234 }, &list);
    try expect(std.mem.eql(u8, list.items, exp[0..]));

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();
    const exp2 = [_]u8{ 1, 1 };
    try serialize(Payload, Payload{ .boolean = true }, &list2);
    try expect(std.mem.eql(u8, list2.items, exp2[0..]));

    // Make sure that the code won't try to serialize untagged
    // payloads.
    const UnTaggedPayload = union {
        int: u64,
        boolean: bool,
    };

    var list3 = ArrayList(u8).init(std.testing.allocator);
    defer list3.deinit();
    if (serialize(UnTaggedPayload, UnTaggedPayload{ .boolean = false }, &list3)) {
        @panic("didn't catch error");
    } else |err| switch (err) {
        error.UnionIsNotTagged => {},
    }
}

test "(de)serializes a type with a custom serialization method" {
    const MyCustomSerializingType = struct {
        len: usize,
        buffer: [100]u8,

        const Self = @This();

        pub fn sszEncode(self: *const Self, list: *ArrayList(u8)) !void {
            try list.append(@truncate(self.len));
            try list.appendSlice(self.buffer[0..self.len]);
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, _: ?std.mem.Allocator) !void {
            if (serialized.len == 0) {
                return error.IndexOutOfBounds;
            }

            out.len = @intCast(serialized[0]);
            if (out.len > serialized.len - 1) {
                return error.IndexOutOfBounds;
            }

            std.mem.copyForwards(u8, out.buffer[0..], serialized[1..]);
        }
    };

    var before: MyCustomSerializingType = .{ .len = 10, .buffer = [_]u8{0} ** 100 };
    before.buffer[0] = 1;
    before.buffer[9] = 100;

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(MyCustomSerializingType, before, &list);

    try expect(list.items.len == 11);

    var after: MyCustomSerializingType = undefined;
    try deserialize(MyCustomSerializingType, list.items, &after, null);

    try expect(before.len == after.len);
    try expect(std.mem.eql(u8, before.buffer[0..before.len], after.buffer[0..after.len]));
}

test "deserializes an u8" {
    const payload = [_]u8{0x55};
    var i: u8 = 0;
    try deserialize(u8, payload[0..payload.len], &i, null);
    try expect(i == 0x55);
}

test "deserializes an u32" {
    const payload = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var i: u32 = 0;
    try deserialize(u32, payload[0..payload.len], &i, null);
    try expect(i == 0x88776655);
}

test "deserializes a boolean" {
    const payload_false = [_]u8{0};
    var b = true;
    try deserialize(bool, payload_false[0..1], &b, null);
    try expect(b == false);

    const payload_true = [_]u8{1};
    try deserialize(bool, payload_true[0..1], &b, null);
    try expect(b == true);
}

test "deserializes a Bitvector[N]" {
    const exp = [_]bool{ true, false, true, true, false, false, false };
    var out = [_]bool{ false, false, false, false, false, false, false };
    const serialized_data = [_]u8{0b00001101};
    try deserialize([7]bool, serialized_data[0..1], &out, null);
    comptime var i = 0;
    inline while (i < 7) : (i += 1) {
        try expect(out[i] == exp[i]);
    }
}

test "deserializes an Optional" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    var out: ?u32 = undefined;
    const exp: ?u32 = 10;
    try serialize(?u32, exp, &list);
    try deserialize(?u32, list.items, &out, null);
    try expect(out.? == exp.?);

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();

    try serialize(?u32, null, &list2);
    try deserialize(?u32, list2.items, &out, null);
    try expect(out == null);
}

test "deserializes a string" {
    const exp = "croissants";

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u8, exp, &list);

    var got: []const u8 = undefined;

    // Deserialize without allocator. The variable
    // must be of type const.
    try deserialize([]const u8, list.items, &got, null);
    try expect(std.mem.eql(u8, exp, got));

    // deserialize with allocator
    var got_var: []u8 = undefined;
    try deserialize([]u8, list.items, &got_var, std.testing.allocator);
    defer std.testing.allocator.free(got_var);
    try expect(std.mem.eql(u8, exp, got));
}

const Pastry = struct {
    name: []const u8,
    weight: u16,
};

const pastries = [_]Pastry{
    Pastry{
        .name = "croissant",
        .weight = 20,
    },
    Pastry{
        .name = "Herrentorte",
        .weight = 500,
    },
};

test "deserializes a structure" {
    var out = Pastry{ .name = "", .weight = 0 };
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try serialize(Pastry, pastries[0], &list);
    try deserialize(Pastry, list.items, &out, null);

    try expect(pastries[0].weight == out.weight);
    try expect(std.mem.eql(u8, pastries[0].name, out.name));
}

test "deserializes a Vector[N]" {
    var out: [2]Pastry = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try serialize([2]Pastry, pastries, &list);
    try deserialize(@TypeOf(pastries), list.items, &out, null);
    comptime var i = 0;
    inline while (i < pastries.len) : (i += 1) {
        try expect(out[i].weight == pastries[i].weight);
        try expect(std.mem.eql(u8, pastries[i].name, out[i].name));
    }
}

test "deserializes an invalid Vector[N] payload" {
    var out: [2]Pastry = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try serialize([2]Pastry, pastries, &list);
    if (deserialize(@TypeOf(pastries), list.items[0 .. list.items.len / 2], &out, null)) {
        @panic("missed error");
    } else |err| switch (err) {
        error.IndexOutOfBounds => {},
        // catch error.NoSerializedFixedSizeAvailable, and a potential allocation error if the API
        // for deserializing slices changes to accept an allocator. None of these errors should
        // happen.
        else => @panic(try std.fmt.allocPrint(std.testing.allocator, "wrong type of error found, err={any}", .{err})),
    }
}

test "deserializes an union" {
    const Payload = union {
        int: u32,
        boolean: bool,
    };

    var p: Payload = undefined;
    try deserialize(Payload, ([_]u8{ 1, 1 })[0..], &p, null);
    try expect(p.boolean == true);

    try deserialize(Payload, ([_]u8{ 1, 0 })[0..], &p, null);
    try expect(p.boolean == false);

    try deserialize(Payload, ([_]u8{ 0, 1, 2, 3, 4 })[0..], &p, null);
    try expect(p.int == 0x04030201);
}

test "serialize/deserialize a u256" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const data = [_]u8{0xAA} ** 32;
    var output: [32]u8 = undefined;

    try serialize([32]u8, data, &list);
    try deserialize([32]u8, list.items, &output, null);

    try expect(std.mem.eql(u8, data[0..], output[0..]));
}

test "(de)serialize a .One pointer in a struct" {
    var a: u32 = 1;
    const b = .{
        .a = &a,
    };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(b), b, &list);
    var c_val: u32 = undefined;
    var c: @TypeOf(b) = .{ .a = &c_val };
    try deserialize(@TypeOf(b), list.items, &c, std.testing.allocator);
    std.testing.allocator.destroy(c.a);
}

test "(de)serialize a slice of structs" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    // force runtime evaluation of the slice using a
    // runtime start and end.
    var start: usize = 0;
    var end: usize = pastries.len;
    _ = .{ &start, &end };

    try serialize([]Pastry, @constCast(pastries[start..end]), &list);

    // pre-allocated deserialization
    var deser_const_pastries: [pastries.len]Pastry = undefined;
    try deserialize([]Pastry, list.items, @constCast(&deser_const_pastries[start..end]), null);

    // allocating deserialization
    var deser_var_pastries: []Pastry = undefined;
    try deserialize([]Pastry, list.items, @constCast(&deser_var_pastries), std.testing.allocator);
    std.testing.allocator.free(deser_var_pastries);
}

test "chunk count of basic types" {
    try expect(chunkCount(bool) == 1);
    try expect(chunkCount(u8) == 1);
    try expect(chunkCount(u16) == 1);
    try expect(chunkCount(u32) == 1);
    try expect(chunkCount(u64) == 1);
}

test "chunk count of Bitvector[N]" {
    try expect(chunkCount([7]bool) == 1);
    try expect(chunkCount([12]bool) == 1);
    try expect(chunkCount([384]bool) == 2);
}

test "chunk count of Vector[B, N]" {
    try expect(chunkCount([17]u32) == 3);
}

test "chunk count of a struct" {
    try expect(chunkCount(Pastry) == 2);
}

test "chunk count of a Vector[C, N]" {
    try expect(chunkCount([2]Pastry) == 2);
}

// used at comptime to generate a bitvector from a byte vector
fn bytesToBits(comptime N: usize, src: [N]u8) [N * 8]bool {
    var bitvector: [N * 8]bool = undefined;
    for (src, 0..) |byte, idx| {
        var i = 0;
        while (i < 8) : (i += 1) {
            bitvector[i + idx * 8] = ((byte >> (7 - i)) & 1) == 1;
        }
    }
    return bitvector;
}

const a_bytes = [_]u8{0xaa} ** 16;
const b_bytes = [_]u8{0xbb} ** 16;
const c_bytes = [_]u8{0xcc} ** 16;
const d_bytes = [_]u8{0xdd} ** 16;
const e_bytes = [_]u8{0xee} ** 16;
const empty_bytes = [_]u8{0} ** 16;

const a_bits = bytesToBits(16, a_bytes);
const b_bits = bytesToBits(16, b_bytes);
const c_bits = bytesToBits(16, c_bytes);
const d_bits = bytesToBits(16, d_bytes);
const e_bits = bytesToBits(16, e_bytes);

test "calculate the root hash of a boolean" {
    var expected = [_]u8{1} ++ [_]u8{0} ** 31;
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(bool, true, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));

    expected = [_]u8{0} ** 32;
    try hashTreeRoot(bool, false, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate root hash of an array of two Bitvector[128]" {
    const deserialized: [2][128]bool = [2][128]bool{ a_bits, b_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(@TypeOf(deserialized), deserialized, &hashed, std.testing.allocator);

    var expected: [32]u8 = undefined;
    const expected_preimage = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    sha256.hash(expected_preimage[0..], &expected, sha256.Options{});

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an array of integers" {
    var expected = [_]u8{ 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xfe, 0xca } ++ [_]u8{0} ** 24;
    var hashed: [32]u8 = undefined;
    try hashTreeRoot([2]u32, [_]u32{ 0xdeadbeef, 0xcafecafe }, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate root hash of an array of three Bitvector[128]" {
    const deserialized: [3][128]bool = [3][128]bool{ a_bits, b_bits, c_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(@TypeOf(deserialized), deserialized, &hashed, std.testing.allocator);

    var left: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    const preimg1 = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    const preimg2 = c_bytes ++ empty_bytes ** 3;
    sha256.hash(preimg1[0..], &left, sha256.Options{});
    sha256.hash(preimg2[0..], &expected, sha256.Options{});
    var digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(expected[0..]);
    digest.final(&expected);

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an array of five Bitvector[128]" {
    const deserialized = [5][128]bool{ a_bits, b_bits, c_bits, d_bits, e_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(@TypeOf(deserialized), deserialized, &hashed, std.testing.allocator);

    var internal_nodes: [64]u8 = undefined;
    var left: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    const preimg1 = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    const preimg2 = c_bytes ++ empty_bytes ++ d_bytes ++ empty_bytes;
    const preimg3 = e_bytes ++ empty_bytes ** 3;
    const preimg4 = empty_bytes ** 4;

    sha256.hash(preimg1[0..], &left, sha256.Options{});
    sha256.hash(preimg2[0..], internal_nodes[0..32], sha256.Options{});
    var digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(internal_nodes[0..32]);
    digest.final(internal_nodes[0..32]);

    sha256.hash(preimg3[0..], &left, sha256.Options{});
    sha256.hash(preimg4[0..], internal_nodes[32..], sha256.Options{});
    digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(internal_nodes[32..]);
    digest.final(internal_nodes[32..]);

    sha256.hash(internal_nodes[0..], &expected, sha256.Options{});

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

const Fork = struct {
    previous_version: [4]u8,
    current_version: [4]u8,
    epoch: u64,
};

test "calculate the root hash of a structure" {
    var hashed: [32]u8 = undefined;
    const fork = Fork{
        .previous_version = [_]u8{ 0x9c, 0xe2, 0x5d, 0x26 },
        .current_version = [_]u8{ 0x36, 0x90, 0x55, 0x93 },
        .epoch = 3,
    };
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected[0..], "58316a908701d3660123f0b8cb7839abdd961f71d92993d34e4f480fbec687d9");
    try hashTreeRoot(Fork, fork, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an Optional" {
    var hashed: [32]u8 = undefined;
    var payload: [64]u8 = undefined;
    const v: ?u32 = null;
    const u: ?u32 = 0xdeadbeef;
    var expected: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(payload[0..], "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], expected[0..], sha256.Options{});
    try hashTreeRoot(?u32, v, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));

    _ = try std.fmt.hexToBytes(payload[0..], "efbeadde000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], expected[0..], sha256.Options{});
    try hashTreeRoot(?u32, u, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an union" {
    const Payload = union(enum) {
        int: u64,
        boolean: bool,
    };
    var out: [32]u8 = undefined;
    var payload: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(payload[0..], "d2040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    var exp1: [32]u8 = undefined;
    sha256.hash(payload[0..], exp1[0..], sha256.Options{});
    try hashTreeRoot(Payload, Payload{ .int = 1234 }, &out, std.testing.allocator);
    try expect(std.mem.eql(u8, out[0..], exp1[0..]));

    var exp2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(payload[0..], "01000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], exp2[0..], sha256.Options{});
    try hashTreeRoot(Payload, Payload{ .boolean = true }, &out, std.testing.allocator);
    try expect(std.mem.eql(u8, out[0..], exp2[0..]));
}

test "(de)serialize List[N] of fixed-length objects" {
    const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
    const ListValidatorIndex = utils.List(u64, MAX_VALIDATORS_PER_COMMITTEE);
    var attesting_indices = try ListValidatorIndex.init(0);
    for (0..10) |i| {
        try attesting_indices.append(i * 100);
    }
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(ListValidatorIndex, attesting_indices, &list);
    var attesting_indices_deser = try ListValidatorIndex.init(0);
    try deserialize(ListValidatorIndex, list.items, &attesting_indices_deser, null);
    try expect(attesting_indices.eql(&attesting_indices_deser));
}

test "(de)serialize List[N] of variable-length objects" {
    const ListOfStrings = utils.List([]const u8, 16);
    var string_list = try ListOfStrings.init(0);
    for (0..10) |i| {
        try string_list.append(try std.fmt.allocPrint(std.testing.allocator, "count={}", .{i}));
    }
    defer for (0..string_list.len()) |i| {
        std.testing.allocator.free(string_list.get(i));
    };
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(ListOfStrings, string_list, &list);
    var string_list_deser = try ListOfStrings.init(0);
    try deserialize(ListOfStrings, list.items, &string_list_deser, null);
    try expect(string_list.len() == string_list_deser.len());
    for (0..string_list.len()) |i| {
        try expect(std.mem.eql(u8, string_list.get(i), string_list_deser.get(i)));
    }
}

test "List[N].fromSlice of structs" {
    const PastryList = utils.List(Pastry, 100);
    var start: usize = 0;
    var end: usize = pastries.len;
    _ = .{ &start, &end };
    const pastry_list = try PastryList.fromSlice(pastries[start..end]);
    for (pastries, 0..) |pastry, i| {
        try expect(std.mem.eql(u8, pastry_list.get(i).name, pastry.name));
        try expect(pastry_list.get(i).weight == pastry.weight);
    }
}

test "(de)serialization of Bitlist[N]" {
    var bitlist = try utils.Bitlist(10).init(0);
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);
    try expect(bitlist.get(1) == false);
    try expect(bitlist.get(2) == true);

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(bitlist), bitlist, &list);
    var bitlist_deser: @TypeOf(bitlist) = undefined;
    try deserialize(@TypeOf(bitlist), list.items, &bitlist_deser, null);
}

test "(de)serialization of Bitlist[N] when N % 8 != 0" {
    var bitlist = try utils.Bitlist(3).init(0);
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);
    try expect(bitlist.get(1) == false);
    try expect(bitlist.get(2) == true);

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(bitlist), bitlist, &list);
    var bitlist_deser: @TypeOf(bitlist) = undefined;
    try deserialize(@TypeOf(bitlist), list.items, &bitlist_deser, null);
    try expect(bitlist.len() == bitlist_deser.len());
    try expect(bitlist.eql(&bitlist_deser));
}

test "structs with nested fixed/variable size u8 array" {
    const Bytes32 = [32]u8;
    var isFixedSizeType = try isFixedSizeObject(Bytes32);
    try expect(isFixedSizeType == true);

    const BytesVar = []u8;
    isFixedSizeType = try isFixedSizeObject(BytesVar);
    try expect(isFixedSizeType == false);

    // 1.1 test for nested but fixed structures
    const FixedBlockBody = struct {
        slot: u64,
        data: [4]u8,
    };
    const FixedBlock = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body: FixedBlockBody,
    };
    const FixedSignedBlock = struct {
        message: FixedBlock,
        signature: [48]u8,
    };
    isFixedSizeType = try isFixedSizeObject(FixedSignedBlock);
    try expect(isFixedSizeType == true);
    const fixed_signed_block = FixedSignedBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .slot = 9, .data = [_]u8{ 1, 2, 3, 4 } },
        },
        .signature = [_]u8{2} ** 48,
    };
    var serialized_fixed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_fixed_block.deinit();
    try serialize(FixedSignedBlock, fixed_signed_block, &serialized_fixed_block);
    // 1.2 verified on an equivalent nodejs container implementation
    const expected_serialized_fixed_block = [_]u8{ 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60, 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231, 9, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
    try expect(std.mem.eql(u8, serialized_fixed_block.items, expected_serialized_fixed_block[0..]));

    var deserialized_fixed_block: FixedSignedBlock = undefined;
    try deserialize(FixedSignedBlock, serialized_fixed_block.items[0..], &deserialized_fixed_block, std.testing.allocator);

    // 1.3 match the individual fields
    try expect(std.mem.eql(u8, fixed_signed_block.signature[0..], deserialized_fixed_block.signature[0..]));
    try expect(fixed_signed_block.message.slot == deserialized_fixed_block.message.slot);
    try expect(fixed_signed_block.message.proposer_index == deserialized_fixed_block.message.proposer_index);
    try expect(std.mem.eql(u8, fixed_signed_block.message.parent_root[0..], deserialized_fixed_block.message.parent_root[0..]));
    try expect(std.mem.eql(u8, fixed_signed_block.message.state_root[0..], deserialized_fixed_block.message.state_root[0..]));
    try expect(fixed_signed_block.message.body.slot == deserialized_fixed_block.message.body.slot);
    try expect(std.mem.eql(u8, fixed_signed_block.message.body.data[0..], deserialized_fixed_block.message.body.data[0..]));

    // 2.1 test for nested variable structures
    const VarBlockBody = struct {
        slot: u64,
        data: []u8,
    };
    const VarBlock = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body: VarBlockBody,
    };
    const VarSignedBlock = struct {
        message: VarBlock,
        signature: [48]u8,
    };
    isFixedSizeType = try isFixedSizeObject(VarSignedBlock);
    try expect(isFixedSizeType == false);

    var varData = [_]u8{ 1, 2, 3, 4 };
    const var_signed_block = VarSignedBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .slot = 9, .data = &varData },
        },
        .signature = [_]u8{2} ** 48,
    };

    var serialized_var_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_var_block.deinit();
    try serialize(VarSignedBlock, var_signed_block, &serialized_var_block);
    // 2.2 verified on an equivalent nodejs container implementation
    const expected_serialized_var_block = [_]u8{ 52, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60, 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231, 84, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 2, 3, 4 };
    try expect(std.mem.eql(u8, serialized_var_block.items, expected_serialized_var_block[0..]));

    var deserialized_var_block: VarSignedBlock = undefined;
    try deserialize(VarSignedBlock, serialized_var_block.items[0..], &deserialized_var_block, std.testing.allocator);
    // how should the things to be de-inited accumulated?
    defer std.testing.allocator.free(deserialized_var_block.message.body.data);

    // 2.3 match the individual fields
    try expect(std.mem.eql(u8, var_signed_block.signature[0..], deserialized_var_block.signature[0..]));
    try expect(var_signed_block.message.slot == deserialized_var_block.message.slot);
    try expect(var_signed_block.message.proposer_index == deserialized_var_block.message.proposer_index);
    try expect(std.mem.eql(u8, var_signed_block.message.parent_root[0..], deserialized_var_block.message.parent_root[0..]));
    try expect(std.mem.eql(u8, var_signed_block.message.state_root[0..], deserialized_var_block.message.state_root[0..]));
    try expect(var_signed_block.message.body.slot == deserialized_var_block.message.body.slot);
    try expect(std.mem.eql(u8, var_signed_block.message.body.data[0..], deserialized_var_block.message.body.data[0..]));
}

test "slice hashtree root composite type" {
    const Root = [32]u8;
    const RootsList = []Root;
    const test_root = [_]u8{23} ** 32;
    // merkelizes as List[Root,1] as dynamic data length is mixed in as bounded type
    var roots_list = [_]Root{test_root};

    var hash_root: [32]u8 = undefined;
    try hashTreeRoot(
        RootsList,
        &roots_list,
        &hash_root,
        std.testing.allocator,
    );
    // computed from nodejs ssz lib for List[Root,1] type
    const expected_hash_root = [_]u8{ 201, 4, 170, 72, 175, 156, 205, 129, 106, 122, 167, 33, 61, 252, 122, 166, 229, 206, 174, 229, 187, 84, 208, 210, 207, 170, 189, 80, 70, 9, 184, 82 };
    try expect(std.mem.eql(u8, &expected_hash_root, &hash_root));
}

test "slice hashtree root simple type" {
    const DynamicRoot = []u8;
    // merkelizes as List[u8,33] as dynamic data length is mixed in as bounded type
    var test_root = [_]u8{23} ** 33;

    var hash_root: [32]u8 = undefined;
    try hashTreeRoot(
        DynamicRoot,
        &test_root,
        &hash_root,
        std.testing.allocator,
    );
    // computed from nodejs ssz lib for List[u8,33]
    const expected_hash_root = [_]u8{ 229, 104, 130, 10, 13, 251, 109, 221, 13, 70, 107, 87, 182, 228, 3, 211, 49, 235, 199, 224, 42, 133, 57, 250, 72, 21, 166, 87, 206, 112, 35, 203 };
    try expect(std.mem.eql(u8, &expected_hash_root, &hash_root));
}

test "List tree root calculation" {
    const ListU64 = utils.List(u64, 1024);

    const empty_list = try ListU64.init(0);
    var list_with_items = try ListU64.init(0);
    try list_with_items.append(42);
    try list_with_items.append(123);
    try list_with_items.append(456);
    const list_with_items_expected = [_]u8{ 0x2e, 0xe6, 0xa2, 0x1f, 0xa8, 0x67, 0x42, 0xfc, 0xef, 0x87, 0x55, 0x7d, 0x48, 0xfe, 0x37, 0x11, 0x9f, 0x94, 0x56, 0xe1, 0xcc, 0x14, 0x37, 0x76, 0x0f, 0x4e, 0x9d, 0x6d, 0xba, 0x84, 0xbe, 0x01 };

    var empty_hash: [32]u8 = undefined;
    var filled_hash: [32]u8 = undefined;

    try hashTreeRoot(ListU64, empty_list, &empty_hash, std.testing.allocator);
    try hashTreeRoot(ListU64, list_with_items, &filled_hash, std.testing.allocator);
    try expect(std.mem.eql(u8, &filled_hash, &list_with_items_expected));

    try expect(!std.mem.eql(u8, &empty_hash, &filled_hash));

    var same_content_list = try ListU64.init(0);
    try same_content_list.append(42);
    try same_content_list.append(123);
    try same_content_list.append(456);

    var same_content_hash: [32]u8 = undefined;
    try hashTreeRoot(ListU64, same_content_list, &same_content_hash, std.testing.allocator);

    try expect(std.mem.eql(u8, &filled_hash, &same_content_hash));
}

test "Bitlist tree root calculation" {
    const TestBitlist = utils.Bitlist(256);

    const empty_bitlist = try TestBitlist.init(0);
    var filled_bitlist = try TestBitlist.init(0);
    try filled_bitlist.append(true);
    try filled_bitlist.append(false);
    try filled_bitlist.append(true);
    try filled_bitlist.append(true);

    var empty_hash: [32]u8 = undefined;
    var filled_hash: [32]u8 = undefined;

    try hashTreeRoot(TestBitlist, empty_bitlist, &empty_hash, std.testing.allocator);
    try hashTreeRoot(TestBitlist, filled_bitlist, &filled_hash, std.testing.allocator);

    try expect(!std.mem.eql(u8, &empty_hash, &filled_hash));

    var same_content_bitlist = try TestBitlist.init(0);
    try same_content_bitlist.append(true);
    try same_content_bitlist.append(false);
    try same_content_bitlist.append(true);
    try same_content_bitlist.append(true);

    var same_content_hash: [32]u8 = undefined;
    try hashTreeRoot(TestBitlist, same_content_bitlist, &same_content_hash, std.testing.allocator);

    try expect(std.mem.eql(u8, &filled_hash, &same_content_hash));
}

test "List of composite types tree root" {
    const ListOfPastry = utils.List(Pastry, 100);

    var pastry_list = try ListOfPastry.init(0);
    try pastry_list.append(Pastry{ .name = "croissant", .weight = 20 });
    try pastry_list.append(Pastry{ .name = "muffin", .weight = 30 });

    var hash1: [32]u8 = undefined;
    try hashTreeRoot(ListOfPastry, pastry_list, &hash1, std.testing.allocator);

    var pastry_list2 = try ListOfPastry.init(0);
    try pastry_list2.append(Pastry{ .name = "croissant", .weight = 20 });
    try pastry_list2.append(Pastry{ .name = "muffin", .weight = 30 });

    var hash2: [32]u8 = undefined;
    try hashTreeRoot(ListOfPastry, pastry_list2, &hash2, std.testing.allocator);

    try expect(std.mem.eql(u8, &hash1, &hash2));

    try pastry_list2.append(Pastry{ .name = "bagel", .weight = 25 });
    var hash3: [32]u8 = undefined;
    try hashTreeRoot(ListOfPastry, pastry_list2, &hash3, std.testing.allocator);

    try expect(!std.mem.eql(u8, &hash1, &hash3));
}

test "serializedSize correctly calculates List/Bitlist sizes" {
    // Test List size calculation
    const ListType = utils.List(u64, 100);
    var list = try ListType.init(0);
    try list.append(123);
    try list.append(456);

    // Verify serializedSize matches actual serialization
    var serialized = ArrayList(u8).init(std.testing.allocator);
    defer serialized.deinit();
    try serialize(ListType, list, &serialized);

    const calculated_size = try serializedSize(ListType, list);
    try expect(calculated_size == serialized.items.len);

    // Test Bitlist size calculation
    const BitlistType = utils.Bitlist(256);
    var bitlist = try BitlistType.init(0);
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);

    var bitlist_serialized = ArrayList(u8).init(std.testing.allocator);
    defer bitlist_serialized.deinit();
    try serialize(BitlistType, bitlist, &bitlist_serialized);

    const bitlist_calculated_size = try serializedSize(BitlistType, bitlist);
    try expect(bitlist_calculated_size == bitlist_serialized.items.len);

    // Test struct containing List/Bitlist
    const StructWithContainers = struct {
        id: u64,
        votes: ListType,
        flags: BitlistType,
    };

    const test_struct = StructWithContainers{
        .id = 42,
        .votes = list,
        .flags = bitlist,
    };

    var struct_serialized = ArrayList(u8).init(std.testing.allocator);
    defer struct_serialized.deinit();
    try serialize(StructWithContainers, test_struct, &struct_serialized);

    const struct_calculated_size = try serializedSize(StructWithContainers, test_struct);
    try expect(struct_calculated_size == struct_serialized.items.len);
}

test "isFixedSizeObject correctly identifies List/Bitlist as variable-size" {
    const ListType = utils.List(u64, 100);
    const BitlistType = utils.Bitlist(100);

    // List and Bitlist should be identified as variable-size per SSZ spec
    try expect(!try isFixedSizeObject(ListType));
    try expect(!try isFixedSizeObject(BitlistType));

    // Struct containing List/Bitlist should also be variable-size
    const StructWithList = struct {
        id: u64,
        votes: ListType,
    };

    try expect(!try isFixedSizeObject(StructWithList));
}

test "Zeam-style List/Bitlist usage with tree root stability" {
    const MAX_VALIDATORS = 2048;
    const MAX_HISTORICAL_BLOCK_HASHES = 4096;

    const Root = [32]u8;

    const Mini3SFCheckpoint = struct {
        root: Root,
        slot: u64,
    };

    const Mini3SFVote = struct {
        validator_id: u64,
        slot: u64,
        head: Mini3SFCheckpoint,
        target: Mini3SFCheckpoint,
        source: Mini3SFCheckpoint,
    };

    const Mini3SFVotes = utils.List(Mini3SFVote, MAX_VALIDATORS);
    const HistoricalBlockHashes = utils.List(Root, MAX_HISTORICAL_BLOCK_HASHES);
    const JustifiedSlots = utils.Bitlist(MAX_HISTORICAL_BLOCK_HASHES);

    const BeamBlockBody = struct {
        votes: Mini3SFVotes,
    };

    const BeamState = struct {
        slot: u64,
        historical_block_hashes: HistoricalBlockHashes,
        justified_slots: JustifiedSlots,
    };

    var votes = try Mini3SFVotes.init(0);
    try votes.append(Mini3SFVote{
        .validator_id = 1,
        .slot = 10,
        .head = Mini3SFCheckpoint{ .root = [_]u8{1} ** 32, .slot = 10 },
        .target = Mini3SFCheckpoint{ .root = [_]u8{2} ** 32, .slot = 9 },
        .source = Mini3SFCheckpoint{ .root = [_]u8{3} ** 32, .slot = 8 },
    });

    var hashes = try HistoricalBlockHashes.init(0);
    try hashes.append([_]u8{0xaa} ** 32);
    try hashes.append([_]u8{0xbb} ** 32);

    var bitlist = try JustifiedSlots.init(0);
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);

    const body = BeamBlockBody{ .votes = votes };
    const state = BeamState{
        .slot = 42,
        .historical_block_hashes = hashes,
        .justified_slots = bitlist,
    };

    var body_hash1: [32]u8 = undefined;
    var body_hash2: [32]u8 = undefined;
    var state_hash1: [32]u8 = undefined;
    var state_hash2: [32]u8 = undefined;

    try hashTreeRoot(BeamBlockBody, body, &body_hash1, std.testing.allocator);
    try hashTreeRoot(BeamBlockBody, body, &body_hash2, std.testing.allocator);
    try hashTreeRoot(BeamState, state, &state_hash1, std.testing.allocator);
    try hashTreeRoot(BeamState, state, &state_hash2, std.testing.allocator);

    try expect(std.mem.eql(u8, &body_hash1, &body_hash2));
    try expect(std.mem.eql(u8, &state_hash1, &state_hash2));
}

test "zeam stf input" {
    const Bytes32 = [32]u8;
    const Bytes48 = [48]u8;
    const ExecutionPayloadHeader = struct {
        timestamp: u64,
    };
    const Mini3SFCheckpoint = struct {
        root: Bytes32,
        slot: u64,
    };
    const Mini3SFVote = struct {
        validator_id: u64,
        slot: u64,
        head: Mini3SFCheckpoint,
        target: Mini3SFCheckpoint,
        source: Mini3SFCheckpoint,
    };
    const BeamBlockBody = struct {
        // some form of APS
        execution_payload_header: ExecutionPayloadHeader,
        // mini 3sf simplified votes
        votes: []Mini3SFVote,
    };
    const BeamBlock = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body: BeamBlockBody,
    };

    const SignedBeamBlock = struct {
        message: BeamBlock,
        // winternitz signature might be of different size depending on num chunks and chunk size
        signature: Bytes48,
    };

    const BeamStateConfig = struct {
        num_validators: u64,
    };
    const BeamBlockHeader = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body_root: Bytes32,
    };
    const BeamState = struct {
        config: BeamStateConfig,
        genesis_time: u64,
        slot: u64,
        latest_block_header: BeamBlockHeader,
        latest_justified: Mini3SFCheckpoint,
        lastest_finalized: Mini3SFCheckpoint,
        historical_block_hashes: []Bytes32,
        justified_slots: []u8,

        // a flat representation of the justifications map
        justifications_roots: []Bytes32,
        justifications_validators: []u8,
    };
    const BeamSTFProverInput = struct {
        block: SignedBeamBlock,
        state: BeamState,
    };

    const config = BeamStateConfig{ .num_validators = 4 };
    const genesis_root = [_]u8{9} ** 32;
    var justifications_roots = [_]Bytes32{genesis_root};
    var justifications_validators = [_]u8{ 0, 1, 1, 1 };

    const state = BeamState{
        .config = config,
        .genesis_time = 93,
        .slot = 99,
        .latest_block_header = .{
            .slot = 0,
            .proposer_index = 0,
            .parent_root = [_]u8{1} ** 32,
            .state_root = [_]u8{2} ** 32,
            .body_root = [_]u8{3} ** 32,
        },
        // mini3sf
        .latest_justified = .{ .root = [_]u8{5} ** 32, .slot = 0 },
        .lastest_finalized = .{ .root = [_]u8{4} ** 32, .slot = 0 },
        .historical_block_hashes = &[_]Bytes32{},
        .justified_slots = &[_]u8{},
        .justifications_roots = &justifications_roots,
        .justifications_validators = &justifications_validators,
    };

    const block = SignedBeamBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .execution_payload_header = ExecutionPayloadHeader{ .timestamp = 23 }, .votes = &[_]Mini3SFVote{} },
        },
        .signature = [_]u8{2} ** 48,
    };

    const prover_input = BeamSTFProverInput{
        .state = state,
        .block = block,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    var serialized = std.ArrayList(u8).init(arena_allocator.allocator());
    defer serialized.deinit();
    try serialize(BeamSTFProverInput, prover_input, &serialized);

    var prover_input_deserialized: BeamSTFProverInput = undefined;
    try deserialize(BeamSTFProverInput, serialized.items[0..], &prover_input_deserialized, arena_allocator.allocator());
    try expect(std.mem.eql(u8, &prover_input.block.message.parent_root, &prover_input_deserialized.block.message.parent_root));
    try expect(std.mem.eql(u8, &prover_input.state.lastest_finalized.root, &prover_input_deserialized.state.lastest_finalized.root));
    try expect(std.mem.eql(u8, prover_input.state.justifications_validators, prover_input_deserialized.state.justifications_validators));
}

// Test uint64 serialization and deserialization
test "serializes uint64" {
    const data: u64 = 0x1122334455667788;
    const serialized_data = [_]u8{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u64, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "deserializes uint64" {
    const data = [_]u8{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    var result: u64 = undefined;
    try deserialize(u64, data[0..], &result, std.testing.allocator);
    try expect(result == 0x1122334455667788);
}

// Test edge cases for integers
test "serialize max/min integer values" {
    // Max u64
    const max_u64: u64 = std.math.maxInt(u64);
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u64, max_u64, &list);
    try expect(list.items.len == 8);
    try expect(std.mem.eql(u8, list.items, &[_]u8{0xFF} ** 8));
    
    // Min i64 (most negative)
    const min_i64: i64 = std.math.minInt(i64);
    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();
    try serialize(i64, min_i64, &list2);
    try expect(list2.items.len == 8);
}

test "Empty List hash tree root" {
    const ListU32 = utils.List(u32, 100);
    const empty_list = try ListU32.init(0);

    var hash: [32]u8 = undefined;
    try hashTreeRoot(ListU32, empty_list, &hash, std.testing.allocator);

    const zig_expected = [_]u8{
        0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30,
        0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09, 0x97, 0x9b,
        0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8,
        0xea, 0x98, 0x31, 0xa9, 0x27, 0x59, 0xfb, 0x4b,
    };
    try expect(std.mem.eql(u8, &hash, &zig_expected));
}

test "List at maximum capacity" {
    const ListU8 = utils.List(u8, 4);
    var full_list = try ListU8.init(0);

    // Fill to capacity
    try full_list.append(1);
    try full_list.append(2);
    try full_list.append(3);
    try full_list.append(4);

    // Should fail to add more
    try std.testing.expectError(error.Overflow, full_list.append(5));

    // Test hash tree root at capacity
    var hash: [32]u8 = undefined;
    try hashTreeRoot(ListU8, full_list, &hash, std.testing.allocator);

    // Python reference: List[uint8, 4] with [1,2,3,4]
    const expected = [_]u8{
        0x95, 0xc1, 0xf6, 0x30, 0xb7, 0xa8, 0x42, 0x8b,
        0x56, 0xd5, 0x1d, 0xa4, 0xdf, 0xae, 0xce, 0x95,
        0x19, 0x67, 0xa7, 0x03, 0x59, 0x68, 0x22, 0x2f,
        0xfb, 0x56, 0x0e, 0x7c, 0x78, 0xcd, 0x42, 0x35,
    };
    try expect(std.mem.eql(u8, &hash, &expected));
}

test "Array hash tree root" {
    const data: [4]u32 = .{ 1, 2, 3, 4 };

    var hash: [32]u8 = undefined;
    try hashTreeRoot([4]u32, data, &hash, std.testing.allocator);

    // Python reference: Vector[uint32, 4] with [1,2,3,4]
    // For basic types packed in one chunk, hash is the serialized data
    const expected = [_]u8{
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try expect(std.mem.eql(u8, &hash, &expected));
}

test "Large Bitvector serialization and hash" {
    const LargeBitvec = [512]bool;
    var data: LargeBitvec = [_]bool{false} ** 512;

    // Set some bits
    data[0] = true;
    data[255] = true;
    data[256] = true;
    data[511] = true;

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(LargeBitvec, data, &list);

    // Should be 512/8 = 64 bytes
    try expect(list.items.len == 64);

    // Check specific bits are set (little-endian bit ordering for serialize)
    try expect(list.items[0] & 0x01 == 0x01); // bit 0 -> LSB of byte 0
    try expect(list.items[31] & 0x80 == 0x80); // bit 255 -> MSB of byte 31
    try expect(list.items[32] & 0x01 == 0x01); // bit 256 -> LSB of byte 32
    try expect(list.items[63] & 0x80 == 0x80); // bit 511 -> MSB of byte 63

    // Test hash tree root
    var hash: [32]u8 = undefined;
    try hashTreeRoot(LargeBitvec, data, &hash, std.testing.allocator);
    const expected = [_]u8{
        0x1d, 0x83, 0x09, 0x11, 0x4a, 0xfe, 0xf7, 0x14,
        0x89, 0xbe, 0x68, 0xd4, 0x5e, 0x18, 0xc3, 0x39,
        0x1f, 0x6e, 0x93, 0x05, 0xb4, 0x57, 0x20, 0x0d,
        0xdc, 0x82, 0xe4, 0x3c, 0x0d, 0x78, 0x35, 0x35,
    };
    try expect(std.mem.eql(u8, &hash, &expected));
}

test "Bitlist edge cases" {
    const TestBitlist = utils.Bitlist(100);

    // All false
    var all_false = try TestBitlist.init(0);
    for (0..50) |_| {
        try all_false.append(false);
    }

    var hash1: [32]u8 = undefined;
    try hashTreeRoot(TestBitlist, all_false, &hash1, std.testing.allocator);

    const expected_false = [_]u8{
        0x02, 0xc8, 0xc1, 0x5f, 0xed, 0x3f, 0x1b, 0x86,
        0xb5, 0xd7, 0x88, 0x0d, 0xe1, 0xfc, 0xbf, 0x45,
        0x12, 0x89, 0x85, 0xc4, 0xf4, 0xb5, 0x49, 0xac,
        0x89, 0x61, 0xcc, 0x39, 0x0d, 0x51, 0x97, 0x2f,
    };
    try expect(std.mem.eql(u8, &hash1, &expected_false));

    // All true
    var all_true = try TestBitlist.init(0);
    for (0..50) |_| {
        try all_true.append(true);
    }

    var hash2: [32]u8 = undefined;
    try hashTreeRoot(TestBitlist, all_true, &hash2, std.testing.allocator);

    // Python reference: Bitlist[100] with 50 true bits
    const expected_true = [_]u8{
        0xa9, 0x85, 0xe0, 0x62, 0x05, 0x71, 0xe7, 0x45,
        0x15, 0xfd, 0x9e, 0xc7, 0x0b, 0x4e, 0xa5, 0x15,
        0x66, 0x3c, 0x55, 0xe0, 0x52, 0xad, 0x24, 0x7f,
        0xc1, 0xf6, 0xdd, 0xe5, 0xe1, 0xe7, 0x0e, 0x67,
    };
    try expect(std.mem.eql(u8, &hash2, &expected_true));
}

test "uint256 hash tree root" {
    const data: u256 = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;

    var hash: [32]u8 = undefined;
    try hashTreeRoot(u256, data, &hash, std.testing.allocator);
    const expected = [_]u8{
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
    };
    try expect(std.mem.eql(u8, &hash, &expected));
}

test "Single element List" {
    const ListU64 = utils.List(u64, 10);
    var single = try ListU64.init(0);
    try single.append(42);

    var hash: [32]u8 = undefined;
    try hashTreeRoot(ListU64, single, &hash, std.testing.allocator);

    const expected = [_]u8{
        0x54, 0xd7, 0x76, 0x7c, 0xc1, 0xdd, 0xd2, 0xf6,
        0x66, 0x8d, 0xcd, 0x00, 0x0c, 0x78, 0xb9, 0xfe,
        0x37, 0xf9, 0x9d, 0x66, 0x2c, 0xfc, 0x5a, 0xc2,
        0x9c, 0x30, 0xfb, 0x0b, 0xb1, 0x28, 0xb1, 0xbc,
    };
    try expect(std.mem.eql(u8, &hash, &expected));
}

test "Nested structure hash tree root" {
    const Inner = struct {
        a: u32,
        b: u64,
    };

    const Outer = struct {
        x: Inner,
        y: u16,
        z: Inner,
    };

    const data = Outer{
        .x = Inner{ .a = 1, .b = 2 },
        .y = 3,
        .z = Inner{ .a = 4, .b = 5 },
    };

    var hash: [32]u8 = undefined;
    try hashTreeRoot(Outer, data, &hash, std.testing.allocator);

    const expected = [_]u8{
        0x4e, 0xbe, 0x9c, 0x7f, 0x41, 0x63, 0xd9, 0x34,
        0xc1, 0x7a, 0x88, 0xa1, 0x38, 0x31, 0x10, 0xce,
        0xac, 0x60, 0x50, 0x5b, 0x84, 0xea, 0xf5, 0x1f,
        0x81, 0xcb, 0xce, 0x0c, 0xe1, 0x9f, 0xc0, 0x43,
    };
    try expect(std.mem.eql(u8, &hash, &expected));
}

test "serialize negative i8 and i16" {
    const val_i8: i8 = -42;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(i8, val_i8, &list);
    try expect(list.items.len == 1);
    try expect(list.items[0] == 0xD6); // Two's complement of -42

    const val_i16: i16 = -1000;
    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();
    try serialize(i16, val_i16, &list2);
    try expect(list2.items.len == 2);
    // -1000 in two's complement is 0xFC18
    try expect(list2.items[0] == 0x18);
    try expect(list2.items[1] == 0xFC);
}

test "Zero-length array" {
    const empty: [0]u32 = .{};

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([0]u32, empty, &list);
    try expect(list.items.len == 0);

    var hash: [32]u8 = undefined;
    try hashTreeRoot([0]u32, empty, &hash, std.testing.allocator);
    // Should be the zero chunk
    try expect(std.mem.eql(u8, &hash, &([_]u8{0} ** 32)));
}
