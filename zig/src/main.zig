const std = @import("std");

const utils = @import("utils");
const set1 = @import("crypto/set1.zig");
const set2 = @import("crypto/set2.zig");

pub fn main() anyerror!void {

    // std.log.info("Nothing to do!", .{});

    // const timer = try std.time.Timer.start();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const ciphertext_split = try utils.load_file(allocator, "data/10.txt");
    const key = "YELLOW SUBMARINE";
    const iv = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const raw_data = try utils.BinaryData.from_byte_arrays(allocator, ciphertext_split);
    const data = try raw_data.decode_from_base_64();
    std.log.info("len: {}", .{data.bytes.len});
    try data.print_hex();
    std.log.info("decryption starting", .{});
    try set2.aes_cbc_dec(data, key[0..], iv[0..]);
    std.log.info("decryption done", .{});
    try data.print_ascii();
}
