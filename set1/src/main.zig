const std = @import("std");

const base_64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn main() anyerror!void {
    const bytes = [3]u8{ 0x49, 0x27, 0x6d };
    three_bytes_to_base_64(bytes);
}

pub fn three_bytes_to_base_64(bytes: [3]u8) void {
    //    const nums = [4]u8{ 0, bytes[0], bytes[1], bytes[2] };

    const num = @byteSwap(u32, @bitCast(u32, [4]u8{ 0, bytes[0], bytes[1], bytes[2] }));

    std.log.debug("in: {b}", .{num});

    const shifts = [4]u5{ 18, 12, 6, 0 };

    for (shifts) |shift_val| {
        const sextet_val = num >> shift_val & 63;

        std.log.debug("out: {c}", .{base_64_alphabet[sextet_val]});
    }
}

test "Wikipedia Test" {
    try std.testing.expectEqual(10, 3 + 7);
}
