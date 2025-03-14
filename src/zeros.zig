// List of root hashes of zero-subtries, up to depth 255.
const std = @import("std");

pub const hashes_of_zero: [256][32]u8 = calc: {
    @setEvalBranchQuota(1000000);
    var ret: [256][32]u8 = undefined;
    var i = 1;
    var src = [_]u8{0} ** 64;
    while (i < 256) : (i += 1) {
        std.crypto.hash.sha2.Sha256.hash(src[0..], ret[i][0..], .{});
        @memcpy(src[0..32], ret[i][0..]);
        @memcpy(src[32..], ret[i][0..]);
        // _ = std.fmt.hexToBytes(ret[i][0..], strs[i - 1]) catch @panic("could not convert hash of zero");
    }

    break :calc ret;
};
