const std = @import("std");

const base_64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const base_64_alphabet_inverse = [256]u8{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, //47
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, //63
    64, 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, //95
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, //127
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
};

pub const BinaryData = struct {
    bytes: []u8 = undefined,
    _bytes: []const u8 = undefined,
    allocator: std.mem.Allocator,

    pub fn apply_single_byte_key(self: *const BinaryData, key: u8) void {
        for (self.bytes) |byte_val, i| {
            self.bytes[i] = byte_val ^ key;
        }
    }
    pub fn apply_repeating_byte_key(self: *const BinaryData, key: []const u8) void {
        for (self.bytes) |byte_val, i| {
            self.bytes[i] = byte_val ^ key[i % key.len];
        }
    }
    pub fn reset_bytes(self: *const BinaryData) void {
        std.mem.copy(u8, self.bytes, self._bytes);
    }
    pub fn from_bytes(allocator: std.mem.Allocator, bytes: []const u8) !BinaryData {
        const bytes_var = try allocator.alloc(u8, bytes.len);
        std.mem.copy(u8, bytes_var, bytes);
        const bytes_const = try allocator.alloc(u8, bytes.len);
        std.mem.copy(u8, bytes_const, bytes);
        const result = BinaryData{ .bytes = bytes_var, ._bytes = bytes_const, .allocator = allocator };
        return result;
    }

    pub fn from_byte_arrays(allocator: std.mem.Allocator, arrays: std.ArrayList([]u8)) !BinaryData {
        var data_size: u32 = 0;
        for (arrays.items) |item| {
            data_size += @intCast(u32, item.len);
        }

        var bytes = try allocator.alloc(u8, data_size);
        var idx: usize = 0;
        for (arrays.items) |item| {
            std.mem.copy(u8, bytes[idx..], item);
            idx += item.len;
        }
        return BinaryData.from_bytes(allocator, bytes);
    }

    pub fn decode_from_base_64(self: *const BinaryData) !BinaryData {
        const bytes = try base_64_to_octets(self.allocator, self.bytes);
        return BinaryData.from_bytes(self.allocator, bytes);
    }
    pub fn decode_from_hex(self: *const BinaryData) !BinaryData {
        const bytes = try hex_string_to_bytes(self.allocator, self.bytes);
        return BinaryData.from_bytes(self.allocator, bytes);
    }
    pub fn to_padded(self: *const BinaryData, keysize: u8) !BinaryData {
        const data_size: usize = self.bytes.len;
        const r: u8 = @intCast(u8, data_size % keysize);
        const padding: u8 = if (r > 0) keysize - r else 0;
        const final_size: usize = data_size + padding;

        var bytes = try self.allocator.alloc(u8, final_size);
        std.mem.copy(u8, bytes, self.bytes);
        var idx = data_size;
        while (idx < final_size) : (idx += 1) {
            bytes[idx] = padding;
        }
        return BinaryData.from_bytes(self.allocator, bytes);
    }

    pub fn print_hex(self: *const BinaryData) !void {
        const out = std.io.getStdOut();

        var writer = out.writer();

        for (self.bytes) |byte_val| {
            try writer.print(" {x} ", .{byte_val});
        }
        try writer.print("\n", .{});
    }

    pub fn print_ascii(self: *const BinaryData) !void {
        const out = std.io.getStdOut();

        var writer = out.writer();

        try writer.print("{s}\n", .{self.bytes});
    }
};

pub fn load_file(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList([]u8) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var reader = buf_reader.reader();
    var buf: [1024]u8 = undefined;
    var list = std.ArrayList([]u8).init(allocator);

    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const line_copy = try allocator.alloc(u8, line.len);
        std.mem.copy(u8, line_copy, line);
        try list.append(line_copy);
    }
    return list;
}

pub fn hex_string_to_bytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    var out_length: usize = @divFloor(hex_str.len, 2);

    if (hex_str.len % 2 != 0) {
        out_length += 1;
    }
    const out_buffer = try allocator.alloc(u8, out_length);

    var char_val: u8 = 0;
    var pos: u8 = 0;
    var buffer: u8 = 0;
    var out_pos: u8 = 0;

    for (hex_str) |char| {
        if (char <= '9' and char >= '0') {
            char_val = char - '0';
        } else if (char <= 'Z' and char >= 'A') {
            char_val = 10 + (char - 'A');
        } else if (char <= 'z' and char >= 'a') {
            char_val = 10 + (char - 'a');
        }

        if (pos == 0) {
            buffer = char_val << 4;
        } else if (pos == 1) {
            buffer = buffer | (char_val & 15);
            out_buffer[out_pos] = buffer;
            out_pos += 1;
        }

        pos = (pos + 1) % 2;
    }
    if (pos != 0) {
        std.log.debug("odd number of digits in hex string, left padding final digit with 0", .{});
        buffer = buffer >> 4;
        out_buffer[out_pos] = buffer;
    }
    return out_buffer;
}

pub fn octets_to_sextets(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var out_length: usize = @divFloor(bytes.len, 3);

    if (bytes.len % 3 != 0) {
        out_length += 1;
    }
    out_length *= 4;

    const out_buffer = try allocator.alloc(u8, out_length);

    var pos: u8 = 0;
    var buffer: u8 = 0;
    const rshifts = [_]u3{ 2, 4, 6 };
    const lshifts = [_]u3{ 4, 2, 0 };
    const masks = [_]u8{ 3, 15, 63 };
    var sextet_val: u8 = 0;
    var out_pos: usize = 0;

    for (bytes) |byte_val| {
        sextet_val = (buffer | (byte_val >> rshifts[pos]));
        buffer = (byte_val & masks[pos]) << lshifts[pos];
        out_buffer[out_pos] = sextet_val;

        if (pos == 2) {
            out_pos += 1;
            out_buffer[out_pos] = buffer;
            buffer = 0;
        }

        out_pos += 1;

        pos = (pos + 1) % 3;
    }

    if (pos != 0 and bytes.len != 0) {
        out_buffer[out_pos] = buffer;
        out_pos += 1;
    }

    while (pos != 0 and pos < 3) {
        out_buffer[out_pos] = 64;
        out_pos += 1;
        pos += 1;
    }
    return out_buffer;
}

pub fn base_64_to_octets(allocator: std.mem.Allocator, input: []u8) ![]u8 {
    var out_length: usize = @divFloor(input.len, 4);

    out_length *= 3;

    var padding: u8 = 0;
    var rear_index: usize = input.len - 3;
    while (rear_index < input.len) : (rear_index += 1) {
        if (input[rear_index] == '=') {
            padding += 1;
        }
    }
    out_length -= padding;

    const octets = try allocator.alloc(u8, out_length);

    var pos: u8 = 0;
    var buffer: u8 = 0;
    const take_masks = [_]u8{ 0x3F, 0x30, 0x3C, 0x3F };
    const lshifts = [_]u3{ 2, 4, 6, 0 };
    const rshifts = [_]u3{ 0, 4, 2, 0 };
    const save_masks = [_]u8{ 0x0, 0x0F, 0x03, 0x0 };
    var octet_val: u8 = 0;
    var out_pos: usize = 0;

    for (input) |char| {
        const sextet_val = base_64_alphabet_inverse[char];
        if (pos == 0) {
            buffer = (sextet_val & take_masks[pos]) << lshifts[pos];
        } else {
            octet_val = buffer | ((sextet_val & take_masks[pos]) >> rshifts[pos]);
            buffer = (sextet_val & save_masks[pos]) << lshifts[pos];

            if (out_pos < octets.len) {
                octets[out_pos] = octet_val;
                out_pos += 1;
            }
        }

        pos = ((pos + 1) % 4);
    }

    return octets;
}

pub fn hamming_distance(a: []const u8, b: []const u8) !u32 {
    if (a.len != b.len) {
        return error.LengthError;
    }
    var index: u8 = 0;
    var total: u32 = 0;

    while (index < a.len) {
        total += @popCount(u8, a[index] ^ b[index]);
        index += 1;
    }
    return total;
}

pub fn score_as_english(bytes: []const u8) f32 {
    var total: i32 = 0;

    for (bytes) |char| {
        var score: i8 = switch (char) {
            'e', 'E', 't', 'T', 'a', 'A', 'o', 'O' => 2,
            'i', 'I', 'n', 'N', ' ', 's', 'S', 'h', 'H', 'r', 'R', 'd', 'D', 'l', 'L', 'u', 'U' => 1,
            else => -1,
        };
        total += score;
    }
    if (total < 0) {
        total = 0;
    }
    return 1 / @intToFloat(f32, total);
}

pub fn xor_bytes(src: []const u8, dst: []u8) !void {
    if (src.len != dst.len) {
        return error.LengthError;
    }
    var index: u8 = 0;
    while (index < src.len) {
        dst[index] = dst[index] ^ src[index];
        index += 1;
    }
}

test "Hamming Distance" {
    const a = "this is a test";
    const b = "wokka wokka!!!";

    try std.testing.expectEqual(hamming_distance(a[0..], b[0..]), 37);
}
test "Sextets to Octets 3" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var input = [_]u8{ 'T', 'W', 'F', 'u' };
    const expected = [_]u8{ 0x4d, 0x61, 0x6e };

    const result = try base_64_to_octets(allocator, input[0..]);

    try std.testing.expectEqualSlices(u8, expected[0..], result[0..]);
}
test "Sextets to Octets 2" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var input = [_]u8{ 'T', 'W', 'E', '=' };
    const expected = [_]u8{ 0x4d, 0x61 };

    const result = try base_64_to_octets(allocator, input[0..]);

    try std.testing.expectEqualSlices(u8, expected[0..], result[0..]);
}
test "Sextets to Octets 1" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var input = [_]u8{ 'T', 'Q', '=', '=' };
    const expected = [_]u8{0x4d};

    const result = try base_64_to_octets(allocator, input[0..]);

    try std.testing.expectEqualSlices(u8, expected[0..], result[0..]);
}

test "Base64 to Sextets" {
    var input = [_]u8{ 'A', 'B', 'C', '/', '=' };

    const expected = [_]u8{ 0, 1, 2, 63, 64 };

    for (input) |char, i| {
        input[i] = base_64_alphabet_inverse[char];
    }

    for (input) |sextet_val, i| {
        try std.testing.expectEqual(expected[i], sextet_val);
    }
}

test "Cryptopals Base64 Encode Test" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Base64 Encode Test No Pad" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d616e";
    const expected = "TWFu";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Base64 Encode Test One Pad" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d61";
    const expected = "TWE=";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}
test "Wikipedia Base64 Encode Test Two Pad" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d";
    const expected = "TQ==";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Base64 Encode Test Repeat" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d616e4d616e";
    const expected = "TWFuTWFu";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Base64 Encode Test Partial Repeat" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d616e4d";
    const expected = "TWFuTQ==";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Base64 Encode Odd Input Length Hex" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d6";
    const expected = "TQY=";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Pad non multiple less" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const expected = [_]u8{ '1', '2', '3', '4', '5', '6', '7', 0x01 };

    const input = try BinaryData.from_bytes(allocator, "1234567");

    const output = try input.to_padded(8);

    try std.testing.expectEqual(expected.len, output.bytes.len);
    try std.testing.expectEqualSlices(u8, output.bytes[0..], expected[0..]);
}

test "Pad exact multiple" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const expected = "12345678";
    const input = try BinaryData.from_bytes(allocator, "12345678");

    const output = try input.to_padded(8);

    try std.testing.expectEqual(expected.len, output.bytes.len);
    try std.testing.expectEqualSlices(u8, output.bytes[0..], expected[0..]);
}

test "Pad non multiple more" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const expected = [_]u8{ '1', '2', '3', '4', '5', '6', '7', '8', '9', 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7 };

    const input = try BinaryData.from_bytes(allocator, "123456789");

    const output = try input.to_padded(8);

    try std.testing.expectEqual(expected.len, output.bytes.len);
    try std.testing.expectEqualSlices(u8, output.bytes[0..], expected[0..]);
}

test "Pad example" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const expected = [_]u8{ 'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E', 0x04, 0x04, 0x04, 0x04 };

    const input = try BinaryData.from_bytes(allocator, "YELLOW SUBMARINE");

    const output = try input.to_padded(20);

    try std.testing.expectEqual(expected.len, output.bytes.len);
    try std.testing.expectEqualSlices(u8, output.bytes[0..], expected[0..]);
}
