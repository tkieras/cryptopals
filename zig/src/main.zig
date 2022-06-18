const std = @import("std");

const utils = @import("utils");
const set1 = @import("crypto/set1.zig");
const set2 = @import("crypto/set2.zig");

pub fn main() anyerror!void {
    //std.log.info("Nothing to do!", .{});
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const encoded_secret = try utils.BinaryData.from_bytes(allocator, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    const secret = try encoded_secret.decode_from_base_64();
    const decrypted_secret = try set2.ecb_secret_decrypt_simple(allocator, secret.bytes);
    // const timer = try std.time.Timer.start();
    std.log.info("{s}", .{decrypted_secret});
}
