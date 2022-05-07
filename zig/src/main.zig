const std = @import("std");

const utils = @import("utils");
const set1 = @import("crypto/set1.zig");

pub fn main() anyerror!void {

    // std.log.info("Nothing to do!", .{});

    // const timer = try std.time.Timer.start();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw_data_split = try utils.load_file(allocator, "data/6.txt");

    const raw_data = try utils.BinaryData.from_byte_arrays(allocator, raw_data_split);

    const data = try raw_data.decode_from_base_64();

    const scored_key = try set1.key_search_multi_byte_xor(allocator, data, 40);

    data.apply_repeating_byte_key(scored_key.key);

    try data.print_ascii();
}
